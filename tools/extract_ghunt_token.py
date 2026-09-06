"""Extract the Android master token from a local GHunt credentials file.

Run this on the machine that actually holds GHunt's logged-in session — NOT
this repo's deploy target, and not any sandboxed CI/dev environment — right
before pushing this branch, or whenever the master token needs replacing.

GHunt stores its session at ~/.malfrats/ghunt/creds.m as base64(json), NOT
further encrypted (verified by reading GHunt's own objects/base.py). Decoded
shape:

    {
      "cookies": {...},
      "osids": {...},
      "android": {
        "master_token": "aas_et/...",
        "authorization_tokens": {...}
      }
    }

This script reads that file and prints ONLY the master token
(data["android"]["master_token"]) to stdout — nothing else in that file
(cookies, other tokens) is ever printed, logged, or otherwise touched. This
module (sentinel_modules/gaia_resolver.py) has no use for anything else in
the file: the master token alone is what mints fresh cookies on demand.

Usage:
    python3 tools/extract_ghunt_token.py
    python3 tools/extract_ghunt_token.py --path /custom/path/to/creds.m

Pipe or copy-paste the printed token straight into
tools/set_integration_credential.py --name google_master_token, which is the
only place it should be stored (encrypted, in the `integrations` table).
"""
import argparse
import base64
import json
import os
import sys

DEFAULT_PATH = os.path.expanduser("~/.malfrats/ghunt/creds.m")


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Extract the Android master token from a local GHunt credentials file.",
    )
    parser.add_argument(
        "--path", default=DEFAULT_PATH,
        help=f"path to GHunt's creds.m (default: {DEFAULT_PATH})",
    )
    return parser


def main(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not os.path.isfile(args.path):
        print(f"No GHunt credentials file found at {args.path}", file=sys.stderr)
        print("Log in with GHunt first, or pass --path to point at the right file.", file=sys.stderr)
        return 1

    with open(args.path, "rb") as fh:
        raw = fh.read().strip()

    try:
        decoded = base64.b64decode(raw)
        data = json.loads(decoded)
    except Exception as exc:
        print(f"Could not parse {args.path} as base64(json): {exc}", file=sys.stderr)
        return 1

    master_token = (data.get("android") or {}).get("master_token")
    if not master_token:
        print(
            f"{args.path} does not contain data['android']['master_token']. "
            "Is this a GHunt credentials file that has completed Android login?",
            file=sys.stderr,
        )
        return 1

    print(master_token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
