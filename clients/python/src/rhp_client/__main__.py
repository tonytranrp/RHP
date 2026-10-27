"""python -m rhp_client: a small command line for scripting against an RHP host.

    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 exec "return 6 * 7"
    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 load low_grav low_grav.lua
    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 call low_grav set 1.6
    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 list
    python -m rhp_client -i dev.rhpid 127.0.0.1:7777 events game.round_over
    python -m rhp_client keygen dev                   # writes dev.rhpid (owner-only), prints the host lines

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


def _write_private(path: str, data: bytes) -> None:
    """Writes `data` to `path` for its owner only: a new temporary file next to it, created exclusively
    with mode 0600, then renamed over `path`. On Windows the mode only sets the read-only flag, so the
    file gets its folder's permissions (a user's own folders are private to that user)."""
    temp = "%s.%d.%s.tmp" % (path, os.getpid(), os.urandom(4).hex())
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def _keygen(argv) -> int:
    parser = argparse.ArgumentParser(prog="python -m rhp_client keygen", description="Write NAME.rhpid: a new identity (pre-shared key and Ed25519 signing key).")
    parser.add_argument("name")
    parser.add_argument("--role", choices=("observe", "patch", "admin"), default="patch", help="the role in the host's keyring line (default patch)")
    parser.add_argument("--show-secret", action="store_true", help="print the keyring line with the pre-shared key (default: it stays in the file)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    path = args.name + ".rhpid"
    if os.path.exists(path):
        print("%s exists; not overwriting it" % path, file=sys.stderr)
        return 1  # as rhp-cli keygen: 1 for a failure, 2 for a usage error
    psk = base64.b64encode(os.urandom(32)).decode()
    text = '# RHP identity (keep it private)\nname = "%s"\npsk = "%s"\nsigning_key = "%s"\n' % (args.name, psk, base64.b64encode(os.urandom(32)).decode())
    try:
        _write_private(path, text.encode("utf-8"))
    except OSError as exc:
        print("can't write %s: %s" % (path, exc), file=sys.stderr)
        return 1
    identity = Identity.parse(text)
    if args.role == "admin":
        print("warning: an admin identity may use the host's whole Lua library (io, os) and admin operations (revert_all, pin); patch loads and calls modules", file=sys.stderr)
    print("wrote %s (keep it private)" % path)
    # The keyring line holds the pre-shared key: it stays in the file unless asked for.
    print("keyring file:  %s %s %s" % (args.name, args.role, psk if args.show_secret else "<psk from %s>" % path))
    print("signers file:  %s %s" % (args.name, base64.b64encode(identity.public_key()).decode()))
    return 0


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["keygen"]:
        return _keygen(argv[1:])

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
