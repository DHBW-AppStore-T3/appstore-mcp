"""Mint a static access token for CI/agents.

    python -m appstore_mcp.mint <name>

Prints the token once on stdout (give it to the agent, e.g. as a CI secret) and the Secret line
`name:sha256` on stderr. Only that hash goes into the cluster (see README).
"""

from __future__ import annotations

import hashlib
import re
import secrets
import sys

from .auth import STATIC_PREFIX


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or not re.fullmatch(r"[a-z0-9][a-z0-9\-]{0,40}", args[0]):
        print("usage: python -m appstore_mcp.mint <name>   (a-z, 0-9, -)", file=sys.stderr)
        return 2
    token = STATIC_PREFIX + secrets.token_urlsafe(32)
    print(token)
    print(f"{args[0]}:{hashlib.sha256(token.encode()).hexdigest()}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
