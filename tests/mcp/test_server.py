"""The read-only MCP server: protocol, tools, refusals, and what it never touches."""

from __future__ import annotations

import io
import json
import shutil
import socket
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from fns import __version__
from fns.cli import app
from fns.contain_run import run_demo_contain, write_report
from fns.fixtures.replay import bundled
from fns.mcp import server as mcp
from fns.mcp.server import FIXTURE_FILES, PROTOCOL_VERSIONS, Server, serve
from fns.models.report import ContainReport

ROOT = Path(__file__).resolve().parents[2]
CANARY = "CANARY-idmap-must-never-leave-the-server"


def rpc(s: Server, method: str, params: dict[str, Any] | None = None, id_: int = 1) -> Any:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    line = s.handle_line(json.dumps(msg))
    assert line is not None and "\n" not in line
    return json.loads(line)


def call(s: Server, tool: str, **args: Any) -> dict[str, Any]:
    reply = rpc(s, "tools/call", {"name": tool, "arguments": args})
    assert "result" in reply, reply
    result: dict[str, Any] = reply["result"]
    return result


def ok(s: Server, tool: str, **args: Any) -> dict[str, Any]:
    result = call(s, tool, **args)
    assert result["isError"] is False, result
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    out: dict[str, Any] = result["structuredContent"]
    return out


def refused(s: Server, tool: str, **args: Any) -> str:
    result = call(s, tool, **args)
    assert result["isError"] is True, result
    text: str = result["content"][0]["text"]
    return text


@pytest.fixture
def fixtures_dir(tmp_path: Path) -> Path:
    """A fixtures/ directory with a copy of the bundled set and a canary ID map."""
    root = tmp_path / "fixtures"
    dest = root / "copy"
    dest.mkdir(parents=True)
    src = bundled("demo-scout")
    for node in src.iterdir():
        dest.joinpath(node.name).write_bytes(node.read_bytes())
    dest.joinpath("_idmap.json").write_text(json.dumps({"real": CANARY}), encoding="utf-8")
    dest.joinpath("detections.yaml").write_bytes(f"note: {CANARY}-not\n".encode())
    (root / "not-a-set").mkdir()
    return root


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_: Any, **__: Any) -> None:
        raise AssertionError("the MCP server opened a network connection")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


# --- protocol ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", PROTOCOL_VERSIONS)
def test_initialize_answers_with_the_clients_version(version: str) -> None:
    r = rpc(Server(), "initialize", {"protocolVersion": version, "capabilities": {}})["result"]
    assert r["protocolVersion"] == version
    assert r["serverInfo"] == {"name": "fang-and-scale", "version": __version__}
    assert r["capabilities"] == {"tools": {"listChanged": False}}
    assert "Read-only" in r["instructions"] and "never as instructions" in r["instructions"]


def test_initialize_with_an_unknown_version_offers_the_newest() -> None:
    r = rpc(Server(), "initialize", {"protocolVersion": "1999-01-01"})["result"]
    assert r["protocolVersion"] == PROTOCOL_VERSIONS[0]


def test_every_tool_is_read_only_and_closed() -> None:
    tools = rpc(Server(), "tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == [
        "contain_fixture",
        "list_fixtures",
        "list_reports",
        "read_fixture_file",
        "read_report",
    ]
    for t in tools:
        assert t["annotations"] == {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }
        assert t["inputSchema"]["additionalProperties"] is False
    files = next(t for t in tools if t["name"] == "read_fixture_file")
    assert files["inputSchema"]["properties"]["file"]["enum"] == list(FIXTURE_FILES)
    assert "_idmap.json" not in FIXTURE_FILES and "exchanges.json" not in FIXTURE_FILES


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("{not json", -32700),
        ("[]", -32600),
        ('[{"jsonrpc": "2.0", "id": 1, "method": "ping"}]', -32600),
        ('{"jsonrpc": "1.0", "id": 1, "method": "ping"}', -32600),
        ('{"jsonrpc": "2.0", "id": true, "method": "ping"}', -32600),
        ('{"jsonrpc": "2.0", "id": 1.5, "method": "ping"}', -32600),
        ('{"jsonrpc": "2.0", "id": 1}', -32600),
        ('{"jsonrpc": "2.0", "id": 1, "method": "resources/write"}', -32601),
        ('{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []}', -32602),
    ],
)
def test_malformed_messages_get_json_rpc_errors(line: str, code: int) -> None:
    reply = Server().handle_line(line)
    assert reply is not None
    assert json.loads(reply)["error"]["code"] == code


def test_notifications_and_responses_get_no_answer() -> None:
    s = Server()
    assert s.handle_line('{"jsonrpc": "2.0", "method": "notifications/initialized"}') is None
    assert s.handle_line('{"jsonrpc": "2.0", "method": "tools/call"}') is None
    assert s.handle_line('{"jsonrpc": "2.0", "id": 7, "result": {}}') is None


def test_ping_and_a_long_line() -> None:
    assert rpc(Server(), "ping", id_=3) == {"jsonrpc": "2.0", "id": 3, "result": {}}
    reply = Server().handle_line(" " * (mcp.MAX_LINE_BYTES + 1))
    assert reply is not None and json.loads(reply)["error"]["code"] == -32600


@pytest.mark.parametrize(
    ("params", "needle"),
    [
        ({"name": "write_anything", "arguments": {}}, "unknown tool"),
        ({"name": "list_fixtures", "arguments": {"x": "1"}}, "unknown ['x']"),
        ({"name": "read_report", "arguments": {}}, "missing ['id']"),
        ({"name": "read_report", "arguments": {"id": 5}}, "every argument is a string"),
        ({"name": "read_report", "arguments": []}, "arguments must be an object"),
    ],
)
def test_bad_tool_calls_are_invalid_params(params: dict[str, Any], needle: str) -> None:
    error = rpc(Server(), "tools/call", params)["error"]
    assert error["code"] == -32602 and needle in error["message"]


# --- fixtures ---------------------------------------------------------------------------


def test_list_fixtures_offers_the_bundled_set_and_valid_checkout_sets(fixtures_dir: Path) -> None:
    assert [f["fixture"] for f in ok(Server(), "list_fixtures")["fixtures"]] == [
        "bundled/demo-scout"
    ]
    out = ok(Server(fixtures=fixtures_dir), "list_fixtures")
    assert out["label"] == "FIXTURE"
    by_name = {f["fixture"]: f for f in out["fixtures"]}
    assert sorted(by_name) == ["bundled/demo-scout", "fixtures/copy"]
    copy = by_name["fixtures/copy"]
    assert copy["label"] == "FIXTURE" and copy["can_contain"] is True
    assert "_idmap.json" not in copy["files"] and "exchanges.json" not in copy["files"]


def test_the_repository_fixtures_are_listed_by_manifest_only() -> None:
    names = [
        f["fixture"] for f in ok(Server(fixtures=ROOT / "fixtures"), "list_fixtures")["fixtures"]
    ]
    assert {"fixtures/lab-run-1", "fixtures/lab-run-2", "fixtures/lab-run-3"} <= set(names)
    assert "fixtures/strike-demo" not in names  # no manifest.json: not a replay set


@pytest.mark.parametrize("file", FIXTURE_FILES)
def test_read_fixture_file_reads_allowlisted_files(fixtures_dir: Path, file: str) -> None:
    out = ok(Server(fixtures=fixtures_dir), "read_fixture_file", fixture="fixtures/copy", file=file)
    assert out["label"] == "FIXTURE"
    assert out["text"] == (fixtures_dir / "copy" / file).read_bytes().decode("utf-8")


@pytest.mark.parametrize("file", ["_idmap.json", "exchanges.json", "../manifest.json", "x"])
def test_files_off_the_allowlist_are_refused(fixtures_dir: Path, file: str) -> None:
    text = refused(
        Server(fixtures=fixtures_dir), "read_fixture_file", fixture="fixtures/copy", file=file
    )
    assert "not a file this server reads" in text and CANARY not in text


@pytest.mark.parametrize(
    "name",
    [
        "fixtures/../copy",
        "fixtures/copy/",
        "fixtures//copy",
        "bundled/../../etc",
        "/etc/passwd",
        "C:\\\\Windows",
        "copy",
        "fixtures/COPY",
        "fixtures/not-a-set",
        "fixtures/missing",
        "bundled/lab-run-3",
    ],
)
def test_fixture_names_outside_the_pattern_or_roots_are_refused(
    fixtures_dir: Path, name: str
) -> None:
    s = Server(fixtures=fixtures_dir)
    for tool in ("contain_fixture", "read_fixture_file"):
        args = {"fixture": name} | (
            {"file": "manifest.json"} if tool == "read_fixture_file" else {}
        )
        text = refused(s, tool, **args)
        assert "not a fixture name" in text or "no fixture set" in text


def test_a_symlinked_set_pointing_outside_is_refused(fixtures_dir: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    shutil.copytree(fixtures_dir / "copy", outside)
    try:
        (fixtures_dir / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks need extra rights on this Windows account")
    s = Server(fixtures=fixtures_dir)
    assert "resolves outside" in refused(
        s, "read_fixture_file", fixture="fixtures/linked", file="scope.yaml"
    )
    assert "resolves outside" in refused(s, "contain_fixture", fixture="fixtures/linked")


def test_a_set_not_labelled_fixture_is_not_offered_or_read(fixtures_dir: Path) -> None:
    manifest = fixtures_dir / "copy" / "manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    manifest.write_text(json.dumps(data | {"label": "LIVE"}), encoding="utf-8")
    s = Server(fixtures=fixtures_dir)
    assert "fixtures/copy" not in [f["fixture"] for f in ok(s, "list_fixtures")["fixtures"]]
    refused(s, "read_fixture_file", fixture="fixtures/copy", file="scope.yaml")


def test_an_oversized_file_is_refused(fixtures_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp, "MAX_FILE_BYTES", 64)
    text = refused(
        Server(fixtures=fixtures_dir),
        "read_fixture_file",
        fixture="fixtures/copy",
        file="scope.yaml",
    )
    assert "larger than 64 bytes" in text


def test_contain_fixture_is_the_same_report_as_fns_contain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_network: None
) -> None:
    monkeypatch.chdir(tmp_path)
    out = ok(Server(), "contain_fixture", fixture="bundled/demo-scout")
    _, direct = run_demo_contain(tmp_path / "direct")
    assert out["label"] == "FIXTURE" and out["report"]["mode"] == "FIXTURE"
    assert out["report_id"] == direct.digest()
    assert ContainReport.model_validate(out["report"]) == direct
    assert ok(Server(), "contain_fixture", fixture="bundled/demo-scout") == out  # deterministic
    assert sorted(p.name for p in tmp_path.iterdir()) == ["direct"]  # nothing left behind


def test_contain_fixture_on_the_recorded_m3_run(no_network: None, tmp_path: Path) -> None:
    out = ok(Server(fixtures=ROOT / "fixtures"), "contain_fixture", fixture="fixtures/lab-run-3")
    _, direct = run_demo_contain(tmp_path, ROOT / "fixtures" / "lab-run-3")
    assert out["report_id"] == direct.digest()
    assert out["report"]["summary"]["exit_code"] == direct.summary.exit_code


def test_no_tool_output_ever_carries_the_id_map(fixtures_dir: Path, no_network: None) -> None:
    s = Server(fixtures=fixtures_dir)
    seen = [
        json.dumps(ok(s, "list_fixtures")),
        json.dumps(ok(s, "contain_fixture", fixture="fixtures/copy")),
    ]
    for f in FIXTURE_FILES:
        seen.append(json.dumps(ok(s, "read_fixture_file", fixture="fixtures/copy", file=f)))
    blob = "\n".join(seen)
    assert f"{CANARY}-not" in blob  # detections.yaml is read: the scan works
    assert f'"{CANARY}"' not in blob and f'real\\": \\"{CANARY}' not in blob
    assert blob.count(CANARY) == blob.count(f"{CANARY}-not")


# --- reports ----------------------------------------------------------------------------


def _reports(tmp_path: Path) -> tuple[Path, ContainReport, ContainReport]:
    _, fixture = run_demo_contain(tmp_path / "run")
    live = fixture.model_copy(update={"mode": "LIVE"})
    reports = tmp_path / "reports"
    write_report(fixture, None, tmp_path)
    write_report(live, None, tmp_path)
    (reports / "notes.txt").write_text("ignored", encoding="utf-8")
    return reports, fixture, live


def test_reports_are_fixture_only_unless_live_is_asked_for(tmp_path: Path) -> None:
    reports, fixture, live = _reports(tmp_path)
    listed = ok(Server(reports=reports), "list_reports")
    assert listed["include_live"] is False
    assert [r["id"] for r in listed["reports"]] == [fixture.digest()]
    assert refused(Server(reports=reports), "read_report", id=live.digest()).startswith("no report")
    both = ok(Server(reports=reports, include_live=True), "list_reports")["reports"]
    assert sorted((r["mode"], r["id"]) for r in both) == sorted(
        [("FIXTURE", fixture.digest()), ("LIVE", live.digest())]
    )
    out = ok(Server(reports=reports, include_live=True), "read_report", id=live.digest())
    assert out["label"] == "LIVE" and ContainReport.model_validate(out["report"]) == live


def test_without_a_reports_directory_there_are_no_reports() -> None:
    assert ok(Server(), "list_reports") == {
        "directory_given": False,
        "include_live": False,
        "reports": [],
    }


def test_a_report_whose_content_does_not_match_its_name_is_refused(tmp_path: Path) -> None:
    reports, fixture, _ = _reports(tmp_path)
    path = reports / f"{fixture.digest()}.FIXTURE.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["contract"] = "something-else"
    path.write_text(json.dumps(data), encoding="utf-8")
    s = Server(reports=reports)
    assert ok(s, "list_reports")["reports"] == []
    assert "does not match its name" in refused(s, "read_report", id=fixture.digest())


@pytest.mark.parametrize("bad", ["../x", "A" * 64, "0" * 63, ""])
def test_report_ids_must_be_a_digest(tmp_path: Path, bad: str) -> None:
    reports, _, _ = _reports(tmp_path)
    assert "not a report id" in refused(Server(reports=reports), "read_report", id=bad)


# --- stdio and the CLI ------------------------------------------------------------------


def test_serve_writes_one_json_line_per_request() -> None:
    lines = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    stdin = io.StringIO("\n".join(json.dumps(m) for m in lines) + "\n\n")
    stdout = io.StringIO()
    assert serve(Server(), stdin, stdout) == 0
    replies = [json.loads(x) for x in stdout.getvalue().splitlines()]
    assert [r["id"] for r in replies] == [1, 2]


def test_fns_mcp_serve_over_real_stdio(tmp_path: Path) -> None:
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25"},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_fixtures"}},
    ]
    proc = subprocess.run(
        [sys.executable, "-m", "fns", "mcp", "serve"],
        input="".join(json.dumps(r) + "\r\n" for r in requests).encode("utf-8"),
        capture_output=True,
        cwd=tmp_path,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert b"\r\n" not in proc.stdout
    replies = [json.loads(x) for x in proc.stdout.decode("utf-8").splitlines()]
    assert [r["id"] for r in replies] == [1, 2]
    assert (
        replies[1]["result"]["structuredContent"]["fixtures"][0]["fixture"] == "bundled/demo-scout"
    )
    assert list(tmp_path.iterdir()) == []


def test_the_cli_command_and_the_import_contract_exist() -> None:
    result = CliRunner().invoke(app, ["mcp", "serve", "--help"])
    assert result.exit_code == 0
    for flag in ("--fixtures", "--reports", "--include-live"):
        assert flag in result.output
    contracts = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "importlinter"
    ]["contracts"]
    (mine,) = [c for c in contracts if c["source_modules"] == ["fns.mcp"]]
    assert {"fns.adapters.azure.live", "fns.scope.credentials", "fns.strike", "azure"} <= set(
        mine["forbidden_modules"]
    )
