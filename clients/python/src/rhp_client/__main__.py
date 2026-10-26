"""python -m rhp_client: a small command line for scripting against an RHP host.

    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 exec "return 6 * 7"
    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 load low_grav low_grav.lua
    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 call low_grav set 1.6
    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 list
    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 events game.round_over
    python -m rhp_client keygen dev                   # writes dev.rhpid, prints the host lines

Values print as JSON-ish Python reprs; call arguments are parsed as JSON when they parse, else
passed as strings. Exit status: 0 ok, 1 an RHP error, 2 bad usage.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys

from . import Identity, RhpError, connect


def _endpoint(text: str):
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit():
        raise argparse.ArgumentTypeError("expected HOST:PORT, got %r" % text)
    return host.strip("[]"), int(port)


def _argument(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text


def _module(text: str):
    return int(text) if text.isdigit() else text


def _keygen(name: str) -> int:
    psk = os.urandom(32)
    seed = os.urandom(32)
    path = name + ".rhpid"
    if os.path.exists(path):
        print("%s exists; not overwriting it" % path, file=sys.stderr)
        return 1  # as rhp-cli keygen: 1 for a failure, 2 for a usage error
    text = '# RHP identity (keep it private)\nname = "%s"\npsk = "%s"\nsigning_key = "%s"\n' % (
        name, base64.b64encode(psk).decode(), base64.b64encode(seed).decode())
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    identity = Identity.parse(text)
    print("wrote %s" % path)
    print("keyring file:  %s admin %s" % (name, base64.b64encode(psk).decode()))
    print("signers file:  %s %s" % (name, base64.b64encode(identity.public_key()).decode()))
    return 0


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["keygen"]:
        if len(argv) != 2:
            print("usage: python -m rhp_client keygen NAME", file=sys.stderr)
            return 2
        return _keygen(argv[1])

    parser = argparse.ArgumentParser(prog="python -m rhp_client", description="Talk to an RHP host.")
    parser.add_argument("-i", "--identity", required=True, help="identity file (rhp-cli keygen / python -m rhp_client keygen)")
    parser.add_argument("--tls", action="store_true", default=None, help="TLS even on loopback (default: TLS except on loopback)")
    parser.add_argument("--plain", action="store_true", help="no TLS (the host must allow it: --insecure-lan)")
    parser.add_argument("--ca", help="check the host's certificate against this CA file")
    parser.add_argument("endpoint", type=_endpoint, help="HOST:PORT")
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("exec")
    p.add_argument("source")
    p = commands.add_parser("load")
    p.add_argument("name")
    p.add_argument("file")
    p = commands.add_parser("call")
    p.add_argument("module", type=_module)
    p.add_argument("function")
    p.add_argument("args", nargs="*", type=_argument)
    p = commands.add_parser("unload")
    p.add_argument("module", type=_module)
    p.add_argument("--force", action="store_true")
    p = commands.add_parser("revert")
    p.add_argument("module", type=_module)
    commands.add_parser("list")
    commands.add_parser("describe")
    p = commands.add_parser("events")
    p.add_argument("names", nargs="+")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0

    tls = False if args.plain else (True if args.tls else None)
    try:
        identity = Identity.load(args.identity)
        host, port = args.endpoint
        with connect(host, port, identity, tls=tls, ca_file=args.ca, on_output=lambda req, line: print(line)) as client:
            if args.command == "exec":
                print(client.exec(args.source))
            elif args.command == "load":
                with open(args.file, encoding="utf-8") as fh:
                    print(client.load(args.name, fh.read()))
            elif args.command == "call":
                print(client.call(args.module, args.function, *args.args))
            elif args.command == "unload":
                print(client.unload(args.module, args.force))
            elif args.command == "revert":
                print(client.revert(args.module))
            elif args.command == "list":
                for status in client.list():
                    print(status)
            elif args.command == "describe":
                print(client.describe())
            elif args.command == "events":
                for name in args.names:
                    client.on(name, lambda e: print("%s %s" % (e.name, e.args), flush=True))
                print("listening (Ctrl+C to stop)", file=sys.stderr)
                try:
                    while client.connected:
                        client._closed.wait(1.0)  # noqa: SLF001 - wait for the session to end
                except KeyboardInterrupt:
                    pass
    except RhpError as exc:
        print(exc, file=sys.stderr)
        if exc.traceback:
            print(exc.traceback, file=sys.stderr)
        return 1
    except OSError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
