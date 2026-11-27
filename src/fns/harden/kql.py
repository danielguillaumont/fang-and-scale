"""A small KQL evaluator, for testing detection rules against sample rows offline.

It understands only what the committed rules use, and refuses everything else
with :class:`KqlUnsupportedError`, so a rule can't quietly go untested:

- statements: ``let Name = <scalar>;`` then one tabular expression;
- operators: ``where``, ``extend``, ``project``, ``summarize`` (no ``by``), and
  ``mv-apply X = <array> on (<operators>)``;
- predicates: ``and``, ``or``, ``not()``, ``==``, ``!=``, ``=~``, ``!~``, ``<``,
  ``<=``, ``>``, ``>=``, ``has``, ``contains``, ``in``, ``in~`` and
  ``between (a .. b)``;
- functions: see ``_FUNCTIONS``; aggregates: see ``_AGGREGATES``.

This is a model of Kusto, not Kusto. A sample that passes here shows the rule's
logic does what its author meant on rows of that shape. It does not show that
Kusto parses the rule, or that real rows have that shape; the live detection
results (M4 session C) are the evidence for that. Where the semantics are
modelled:

- a comparison involving null is null, and ``where`` keeps a row only on
  ``true``;
- a column the row doesn't have is an error, not null, so samples must carry
  every column a rule reads;
- ``summarize`` with no ``by`` returns one row even on empty input, with
  ``count``/``sum`` 0 and ``make_set``/``make_list`` empty, as Kusto documents.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

Row = dict[str, Any]


class KqlError(ValueError):
    """The query is malformed, or a row lacks a column the query reads."""


class KqlUnsupportedError(KqlError):
    """The query uses KQL this evaluator does not model."""


# --- tokens -----------------------------------------------------------------------


@dataclass(frozen=True)
class Tok:
    kind: str  # "id", "str", "num", "dyn", "op", "end"
    value: Any
    pos: int


_TOKEN: Final = re.compile(
    r"""
    (?P<ws>\s+|//[^\n]*)
  | (?P<dyn>dynamic\s*\()
  | (?P<str>"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<id>mv-apply|in~|!in~|!in|!has|!contains|[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>\.\.|==|!=|=~|!~|>=|<=|[|()\[\],.=<>;])
    """,
    re.X,
)


def _unquote(text: str) -> str:
    body = text[1:-1]
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m[1], m[1]), body)


def _dynamic_literal(query: str, start: int) -> tuple[Any, int]:
    """Parse ``dynamic(<json>)`` from ``start`` (just after the ``(``)."""
    depth, i, quote = 1, start, ""
    while i < len(query):
        c = query[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    if depth:
        raise KqlError("unclosed dynamic(")
    raw = query[start:i].strip()
    try:
        return (None if raw == "null" else json.loads(raw)), i + 1
    except json.JSONDecodeError as exc:
        raise KqlUnsupportedError(f"dynamic literal is not JSON: {raw!r}") from exc


def tokenize(query: str) -> list[Tok]:
    toks: list[Tok] = []
    i = 0
    while i < len(query):
        m = _TOKEN.match(query, i)
        if not m:
            raise KqlUnsupportedError(f"unexpected character {query[i]!r} at {i}")
        kind = m.lastgroup or ""
        if kind == "ws":
            i = m.end()
            continue
        if kind == "dyn":
            value, i = _dynamic_literal(query, m.end())
            toks.append(Tok("dyn", value, m.start()))
            continue
        text = m.group()
        if kind == "str":
            toks.append(Tok("str", _unquote(text), m.start()))
        elif kind == "num":
            toks.append(Tok("num", float(text) if "." in text else int(text), m.start()))
        else:
            toks.append(Tok(kind, text, m.start()))
        i = m.end()
    toks.append(Tok("end", None, len(query)))
    return toks


# --- values -----------------------------------------------------------------------


def tostring(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return v
    if isinstance(v, int | float):
        return str(v)
    return json.dumps(v, separators=(",", ":"), sort_keys=False)


def _todynamic(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    try:
        return json.loads(v)
    except json.JSONDecodeError:
        return None


def _is_num(v: Any) -> bool:
    return isinstance(v, int | float) and not isinstance(v, bool)


def _term_match(haystack: str, needle: str) -> bool:
    if not needle:
        return True
    pattern = rf"(?<![A-Za-z0-9]){re.escape(needle)}(?![A-Za-z0-9])"
    return re.search(pattern, haystack, re.I) is not None


def _flatten(values: Sequence[Any]) -> list[Any]:
    out: list[Any] = []
    for v in values:
        out.extend(v if isinstance(v, list) else [v])
    return out


def _cmp(op: str, a: Any, b: Any) -> bool | None:
    if a is None or b is None:
        return None
    if op in ("==", "!="):
        same = (_is_num(a) and _is_num(b)) or type(a) is type(b) in (str, bool)
        if same:
            eq = bool(a == b)
        else:
            raise KqlError(f"cannot compare {type(a).__name__} with {type(b).__name__}")
        return eq if op == "==" else not eq
    if op in ("=~", "!~"):
        eq = tostring(a).lower() == tostring(b).lower()
        return eq if op == "=~" else not eq
    if not (_is_num(a) and _is_num(b)):
        raise KqlError(f"{op} needs numbers")
    return bool({"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op])


def _and(a: Any, b: Any) -> bool | None:
    if a is False or b is False:
        return False
    if a is True and b is True:
        return True
    return None


def _or(a: Any, b: Any) -> bool | None:
    if a is True or b is True:
        return True
    if a is False and b is False:
        return False
    return None


def _not(a: Any) -> bool | None:
    return None if a is None else not a


def _array_length(v: Any) -> int | None:
    return len(v) if isinstance(v, list) else None


def _case(*args: Any) -> Any:
    if len(args) < 3 or len(args) % 2 == 0:
        raise KqlError("case() needs pairs and an else value")
    for i in range(0, len(args) - 1, 2):
        if args[i] is True:
            return args[i + 1]
    return args[-1]


def _strcat_array(arr: Any, delim: Any) -> str:
    if not isinstance(arr, list):
        return ""
    return tostring(delim).join(tostring(x) for x in arr)


_FUNCTIONS: Final[dict[str, Callable[..., Any]]] = {
    "tostring": tostring,
    "todynamic": _todynamic,
    "parse_json": _todynamic,
    "tolower": lambda v: tostring(v).lower(),
    "toupper": lambda v: tostring(v).upper(),
    "isempty": lambda v: v is None or v == "",
    "isnotempty": lambda v: not (v is None or v == ""),
    "isnull": lambda v: v is None,
    "isnotnull": lambda v: v is not None,
    "array_length": _array_length,
    "iff": lambda p, a, b: a if p is True else b,
    "iif": lambda p, a, b: a if p is True else b,
    "case": _case,
    "strcat": lambda *a: "".join(tostring(x) for x in a),
    "strcat_array": _strcat_array,
    "not": _not,
}

_AGGREGATES: Final = frozenset({"count", "countif", "sum", "sumif", "make_set", "make_list"})


# --- expressions ------------------------------------------------------------------

Expr = Callable[[Row, dict[str, Any]], Any]
"""An expression: (row, let-bindings) -> value."""


def _const(value: Any) -> Expr:
    return lambda r, e: value


def _col(name: str) -> Expr:
    return lambda r, e: _column(r, e, name)


def _binary(f: Callable[[Any, Any], Any], a: Expr, b: Expr) -> Expr:
    return lambda r, e: f(a(r, e), b(r, e))


@dataclass(frozen=True)
class Agg:
    name: str
    args: tuple[Expr, ...]


class _Parser:
    def __init__(self, toks: list[Tok]) -> None:
        self.toks = toks
        self.i = 0

    def peek(self, offset: int = 0) -> Tok:
        return self.toks[min(self.i + offset, len(self.toks) - 1)]

    def next(self) -> Tok:
        t = self.peek()
        self.i += 1
        return t

    def at(self, kind: str, value: Any = None) -> bool:
        t = self.peek()
        return t.kind == kind and (value is None or t.value == value)

    def expect(self, kind: str, value: Any = None) -> Tok:
        if not self.at(kind, value):
            t = self.peek()
            want = value if value is not None else kind
            raise KqlError(f"expected {want!r} at {t.pos}, found {t.value!r}")
        return self.next()

    def ident(self) -> str:
        return str(self.expect("id").value)

    # expressions, lowest precedence first

    def expr(self) -> Expr:
        left = self.and_expr()
        while self.at("id", "or"):
            self.next()
            right = self.and_expr()
            left = _binary(_or, left, right)
        return left

    def and_expr(self) -> Expr:
        left = self.cmp_expr()
        while self.at("id", "and"):
            self.next()
            right = self.cmp_expr()
            left = _binary(_and, left, right)
        return left

    def cmp_expr(self) -> Expr:
        left = self.postfix()
        t = self.peek()
        if t.kind == "op" and t.value in ("==", "!=", "=~", "!~", "<", "<=", ">", ">="):
            self.next()
            right = self.postfix()
            op = str(t.value)
            return _binary(lambda a, b: _cmp(op, a, b), left, right)
        if t.kind != "id":
            return left
        word = str(t.value)
        if word in ("has", "!has", "contains", "!contains"):
            self.next()
            right = self.postfix()
            negate = word.startswith("!")
            term = word.lstrip("!") == "has"

            def text_op(r: Row, e: dict[str, Any]) -> bool | None:
                a, b = left(r, e), right(r, e)
                if a is None:
                    return None
                hay, needle = tostring(a), tostring(b)
                hit = _term_match(hay, needle) if term else needle.lower() in hay.lower()
                return not hit if negate else hit

            return text_op
        if word in ("in", "in~", "!in", "!in~"):
            self.next()
            items = self.call_args()
            fold = word.endswith("~")
            negate = word.startswith("!")

            def in_op(r: Row, e: dict[str, Any]) -> bool | None:
                a = left(r, e)
                if a is None:
                    return None
                vals = _flatten([f(r, e) for f in items])
                if fold:
                    hit = tostring(a).lower() in {tostring(v).lower() for v in vals}
                else:
                    hit = any(_cmp("==", a, v) is True for v in vals if v is not None)
                return not hit if negate else hit

            return in_op
        if word == "between":
            self.next()
            self.expect("op", "(")
            lo = self.postfix()
            self.expect("op", "..")
            hi = self.postfix()
            self.expect("op", ")")

            def between(r: Row, e: dict[str, Any]) -> bool | None:
                return _and(_cmp(">=", left(r, e), lo(r, e)), _cmp("<=", left(r, e), hi(r, e)))

            return between
        return left

    def call_args(self) -> list[Expr]:
        self.expect("op", "(")
        args: list[Expr] = []
        if not self.at("op", ")"):
            args.append(self.expr())
            while self.at("op", ","):
                self.next()
                args.append(self.expr())
        self.expect("op", ")")
        return args

    def postfix(self) -> Expr:
        base = self.primary()
        while True:
            if self.at("op", "."):
                self.next()
                key = self.ident()
                base = _binary(_member, base, _const(key))
            elif self.at("op", "["):
                self.next()
                index = self.expr()
                self.expect("op", "]")
                base = _binary(_member, base, index)
            else:
                return base

    def primary(self) -> Expr:
        t = self.next()
        if t.kind in ("str", "num", "dyn"):
            return _const(t.value)
        if t.kind == "op" and t.value == "(":
            inner = self.expr()
            self.expect("op", ")")
            return inner
        if t.kind != "id":
            raise KqlError(f"unexpected {t.value!r} at {t.pos}")
        name = str(t.value)
        if name in ("true", "false"):
            return _const(name == "true")
        if self.at("op", "("):
            if name in _AGGREGATES:
                raise KqlError(f"{name}() is an aggregate; use it in summarize")
            fn = _FUNCTIONS.get(name)
            if fn is None:
                raise KqlUnsupportedError(f"function {name}() is not modelled")
            args = self.call_args()
            return lambda r, e: fn(*(a(r, e) for a in args))
        return _col(name)

    def aggregate(self) -> tuple[str, Agg]:
        out = self.ident()
        self.expect("op", "=")
        name = self.ident()
        if name not in _AGGREGATES:
            raise KqlUnsupportedError(f"aggregate {name}() is not modelled")
        return out, Agg(name, tuple(self.call_args()))


def _member(v: Any, key: Any) -> Any:
    if isinstance(v, dict) and isinstance(key, str):
        return v.get(key)
    if isinstance(v, list) and _is_num(key) and isinstance(key, int):
        return v[key] if -len(v) <= key < len(v) else None
    return None


def _column(row: Row, env: dict[str, Any], name: str) -> Any:
    if name in row:
        return row[name]
    if name in env:
        return env[name]
    raise KqlError(f"unknown column or name {name!r}")


# --- tabular operators ------------------------------------------------------------

Op = Callable[[list[Row], dict[str, Any]], list[Row]]


def _assignments(p: _Parser, allow_bare: bool) -> list[tuple[str, Expr]]:
    items: list[tuple[str, Expr]] = []
    while True:
        name = p.ident()
        if p.at("op", "="):
            p.next()
            items.append((name, p.expr()))
        elif allow_bare:
            items.append((name, _col(name)))
        else:
            raise KqlError(f"expected '=' after {name!r}")
        if not p.at("op", ","):
            return items
        p.next()


def _run_agg(agg: Agg, rows: list[Row], env: dict[str, Any]) -> Any:
    if agg.name == "count":
        return len(rows)
    if agg.name == "countif":
        return sum(1 for r in rows if agg.args[0](r, env) is True)
    if agg.name in ("sum", "sumif"):
        total: int | float = 0
        for r in rows:
            if agg.name == "sumif" and agg.args[1](r, env) is not True:
                continue
            v = agg.args[0](r, env)
            if v is None:
                continue
            if not _is_num(v):
                raise KqlError(f"{agg.name}() over a non-number")
            total += v
        return total
    values = [agg.args[0](r, env) for r in rows]
    if agg.name == "make_list":
        return values
    seen: list[Any] = []
    for v in values:
        if v not in seen:
            seen.append(v)
    return seen


def _operator(p: _Parser) -> Op:
    word = p.ident()
    if word == "where":
        pred = p.expr()
        return lambda rows, env: [r for r in rows if pred(r, env) is True]
    if word == "extend":
        items = _assignments(p, allow_bare=False)

        def extend(rows: list[Row], env: dict[str, Any]) -> list[Row]:
            out: list[Row] = []
            for r in rows:
                new = dict(r)
                for name, f in items:
                    new[name] = f(new, env)
                out.append(new)
            return out

        return extend
    if word == "project":
        items = _assignments(p, allow_bare=True)
        return lambda rows, env: [{n: f(r, env) for n, f in items} for r in rows]
    if word == "summarize":
        aggs = [p.aggregate()]
        while p.at("op", ","):
            p.next()
            aggs.append(p.aggregate())
        if p.at("id", "by"):
            raise KqlUnsupportedError("summarize ... by is not modelled")
        return lambda rows, env: [{n: _run_agg(a, rows, env) for n, a in aggs}]
    if word == "mv-apply":
        name = p.ident()
        p.expect("op", "=")
        source = p.expr()
        p.expect("id", "on")
        p.expect("op", "(")
        sub = _pipeline(p)
        p.expect("op", ")")

        def mv_apply(rows: list[Row], env: dict[str, Any]) -> list[Row]:
            out: list[Row] = []
            for r in rows:
                arr = source(r, env)
                items = arr if isinstance(arr, list) else []
                result = [{name: x} for x in items]
                for op in sub:
                    result = op(result, {**env, **r})
                out.extend({**r, **x} for x in result)
            return out

        return mv_apply
    raise KqlUnsupportedError(f"operator {word!r} is not modelled")


def _pipeline(p: _Parser) -> list[Op]:
    ops = [_operator(p)]
    while p.at("op", "|"):
        p.next()
        ops.append(_operator(p))
    return ops


@dataclass(frozen=True)
class Query:
    lets: tuple[tuple[str, Expr], ...]
    table: str
    ops: tuple[Op, ...]

    def run(self, tables: dict[str, list[Row]]) -> list[Row]:
        env: dict[str, Any] = {}
        for name, f in self.lets:
            env[name] = f({}, env)
        if self.table not in tables:
            raise KqlError(f"no rows given for table {self.table!r}")
        rows = [dict(r) for r in tables[self.table]]
        for op in self.ops:
            rows = op(rows, env)
        return rows


def parse(query: str) -> Query:
    p = _Parser(tokenize(query))
    lets: list[tuple[str, Expr]] = []
    while p.at("id", "let"):
        p.next()
        name = p.ident()
        p.expect("op", "=")
        lets.append((name, p.expr()))
        p.expect("op", ";")
    table = p.ident()
    ops: list[Op] = []
    while p.at("op", "|"):
        p.next()
        ops.append(_operator(p))
    if p.at("op", ";"):
        p.next()
    p.expect("end")
    return Query(tuple(lets), table, tuple(ops))


def run(query: str, tables: dict[str, list[Row]]) -> list[Row]:
    return parse(query).run(tables)
