"""Probes (M3): ask the platform, or try a non-destructive read, as the test identity.

Executor side of the trust boundary: ``fns.verify`` never imports this package.
Live probes go through the scope gate; ``MockProbe`` replays a FIXTURE results file.
"""
