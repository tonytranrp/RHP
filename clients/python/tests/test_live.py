"""End to end against RHP's own C++ host (Examples/headless_server). Set RHP_HEADLESS_SERVER to the
built executable (RHP's ctest does); without it these tests are skipped.

    RHP_HEADLESS_SERVER=build/windows-msvc/Examples/headless_server/Debug/headless_server.exe pytest
"""

import base64
import os
import subprocess
import threading
import time

import pytest

import rhp_client as rhp
from rhp_client.identity import Identity

SERVER = os.environ.get("RHP_HEADLESS_SERVER")
# The build's hardening level (RHP's ctest sets it): production refuses unsigned observe code and
# has no remote debugger.
HARDENING = os.environ.get("RHP_HARDENING", "dev")
pytestmark = pytest.mark.skipif(not SERVER or not os.path.exists(SERVER), reason="RHP_HEADLESS_SERVER isn't set")


def new_identity(name, signing=True):
    return Identity(name, os.urandom(32), os.urandom(32) if signing else None)


class Host:
    def __init__(self, tmp, extra=()):
        self.dev = new_identity("dev")
        self.observer = new_identity("watcher", signing=False)
        self.stranger = new_identity("stranger")  # signs, but the host doesn't trust its key
        keys = tmp / "keys.txt"
        keys.write_text("dev admin %s\nwatcher observe %s\nstranger patch %s\n" % (
            base64.b64encode(self.dev.psk).decode(), base64.b64encode(self.observer.psk).decode(), base64.b64encode(self.stranger.psk).decode()))
        signers = tmp / "signers.pub"
        signers.write_text("dev %s\n" % base64.b64encode(self.dev.public_key()).decode())
        self.port_file = tmp / "port.txt"
        self.stop_file = tmp / "stop"
        self.process = subprocess.Popen([SERVER, "--port", "0", "--keys", str(keys), "--signers", str(signers), "--port-file", str(self.port_file),
                                         "--stop-file", str(self.stop_file), "--seconds", "120", *extra],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 20
        while not self.port_file.exists() or not self.port_file.read_text().strip():
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("headless_server didn't start: %s" % self.process.stdout.read().decode(errors="replace"))
            time.sleep(0.05)
        self.port = int(self.port_file.read_text().strip())

    def connect(self, identity=None, **options):
        return rhp.connect("127.0.0.1", self.port, identity or self.dev, **options)

    def stop(self):
        self.stop_file.write_text("")
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


@pytest.fixture
def host(tmp_path):
    h = Host(tmp_path)
    yield h
    h.stop()


def test_exec_load_call_and_revert(host):
    lines = []
    with host.connect(on_output=lambda req, line: lines.append(line)) as c:
        assert c.role == "admin"
        assert c.exec("return 6 * 7") == [42]
        assert c.exec("return 1, 'two', {3, x = true}, nil") == [1, "two", {1: 3, "x": True}, None]
        mod = c.load("py.score", "local M = {} function M.add(n) game.add_score(n) print('added', n) return game.score end return M")
        assert isinstance(mod, int) and mod > 0
        before = c.exec("return game.score")[0]
        assert c.call(mod, "add", 5) == [before + 5]
        assert c.call("py.score", "add", 2) == [before + 7]
        assert "added\t5" in lines
        status = c.status(mod)
        assert status.name == "py.score" and status.state == "active" and status.effects >= 2
        assert any(m.name == "py.score" for m in c.list())
        assert "game" in c.describe()
        summary = c.unload(mod)
        assert summary.undone >= 2 and summary.clean
        assert c.exec("return game.score") == [before]


def test_errors_arrive_as_rhp_errors(host):
    with host.connect() as c:
        with pytest.raises(rhp.RhpError) as syntax:
            c.exec("return +")
        assert syntax.value.code == "compile"
        with pytest.raises(rhp.RhpError) as runtime:
            c.exec("error('boom')")
        assert runtime.value.code == "runtime" and "boom" in runtime.value.message
        with pytest.raises(rhp.RhpError) as missing:
            c.call("no.such.module", "f")
        assert missing.value.code == "not_found"
        assert c.exec("return 'still fine'") == ["still fine"]


def test_signatures_and_roles(host):
    with host.connect(host.observer) as watcher:  # observe: unsigned code runs (below production), nothing may change
        assert watcher.role == "observe"
        if HARDENING == "production":
            with pytest.raises(rhp.RhpError) as unsigned:
                watcher.exec("return game.tick ~= nil")
            assert unsigned.value.code == "bad_signature"
        else:
            assert watcher.exec("return game.tick ~= nil") == [True]
            with pytest.raises(rhp.RhpError) as forbidden:
                watcher.exec("game.gravity = 1")
            assert forbidden.value.code == "forbidden"
    with host.connect(host.stranger) as stranger:  # its key isn't a trusted signer
        with pytest.raises(rhp.RhpError) as bad:
            stranger.exec("return 1")
        assert bad.value.code == "bad_signature"
    with pytest.raises(rhp.RhpError) as auth:  # a key the host doesn't know at all
        host.connect(new_identity("dev"))
    assert auth.value.code in ("auth", "transport")


def test_events_and_cancel(host):
    with host.connect() as c:
        got = []
        arrived = threading.Event()

        def on_tick(event):
            got.append(event)
            arrived.set()

        c.on("py.tick", on_tick)
        mod = c.load("py.publisher", "rhp.every_frame(function() rhp.publish('py.tick', rhp.frame(), 'x') end)")
        assert arrived.wait(10)
        assert got[0].name == "py.tick" and got[0].args[1] == "x" and got[0].module == mod
        c.unload(mod)

        spin = c.exec_async("while true do end")
        time.sleep(0.2)
        c.cancel(spin)
        with pytest.raises(rhp.RhpError) as cancelled:
            spin.result(10)
        assert cancelled.value.code == "cancelled"
        assert c.exec("return 'after cancel'") == ["after cancel"]


def test_concurrent_requests_from_threads(host):
    with host.connect() as c:
        results = [None] * 16

        def work(i):
            results[i] = c.exec("return %d * 2" % i)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results == [[i * 2] for i in range(16)]


def test_resume_after_a_dropped_connection(host):
    with host.connect() as c:
        assert c.exec("kept = 41 return kept") == [41]
        c._session._stream.close()  # noqa: SLF001 - drop the link under the session
        assert c.exec("return kept + 1") == [42]  # same session: the scratch module kept its global


def test_tunables_and_profiler(host):
    with host.connect() as c:
        tunables = {t.path: t for t in c.tunables("game")}
        assert "game.gravity" in tunables and tunables["game.gravity"].writable
        c.tune("game.gravity", 1.5)
        assert c.exec("return game.gravity") == [1.5]
        with pytest.raises(rhp.RhpError) as missing:
            c.tune("game.nope", 1)
        assert missing.value.code == "not_found"

        assert c.profile("start", 200).running
        c.load("py.work", "function spin()\n  local s = 0\n  for i = 1, 50000 do s = s + i end\n  return s\nend")
        c.call("py.work", "spin")
        report = c.profile("stop")
        assert not report.running and report.samples > 50
        assert report.truncated == 0  # a small profile fits one reply
        assert any("spin (py.work:1)" in stack for stack, _ in report.stacks)
        assert report.folded().count("\n") == len(report.stacks)
        with pytest.raises(rhp.RhpError) as releases:
            c.release_status()  # this host serves no release manager
        assert releases.value.code == "not_found"


@pytest.mark.skipif(HARDENING == "production", reason="the remote debugger is compiled out of production builds")
def test_debugger(host):
    with host.connect() as c:
        paused = threading.Event()
        c.on("rhp.debug", lambda e: paused.set() if e.args and e.args[0].get("kind") == "paused" else None)
        c.load("py.dbg", "function add(a, b)\n  local sum = a + b\n  return sum\nend")
        assert c.debug("break", source="py.dbg", lines=[3])["lines"] == [3]
        call = c.call_async("py.dbg", "add", 2, 5)
        assert paused.wait(10)
        stop = c.debug("paused")["paused"][0]
        assert stop["line"] == 3 and stop["reason"] == "breakpoint"
        assert c.debug("stack", request=stop["request"])["frames"][0]["name"] == "add"
        names = {v["name"]: v["text"] for v in c.debug("variables", request=stop["request"])["variables"]}
        assert names["sum"] == "7"
        assert c.debug("evaluate", request=stop["request"], expression="a")["variables"][0]["text"] == "2"
        c.debug("continue", request=stop["request"])
        assert call.result(10) == [7]


@pytest.fixture
def blob_host(tmp_path):
    (tmp_path / "h").mkdir()
    blobs = tmp_path / "blobs"
    blobs.mkdir()
    h = Host(tmp_path / "h", ("--blobs", str(blobs)))
    yield h, blobs
    h.stop()


def test_blob_upload(blob_host):
    h, blobs = blob_host
    data = os.urandom(200_000)
    with h.connect() as c:
        c.blob("files", "payload.bin", data, chunk=32 * 1024)
    assert (blobs / "payload.bin").read_bytes() == data


def test_tls(tmp_path):
    pytest.importorskip("OpenSSL")
    (tmp_path / "h").mkdir()
    h = Host(tmp_path / "h", ("--tls",))
    try:
        with h.connect(tls=True) as c:
            assert c.exec("return 'over tls'") == ["over tls"]
            c._session._stream.close()  # noqa: SLF001 - resume over a new TLS connection (a new binding)
            assert c.exec("return 'resumed over tls'") == ["resumed over tls"]
    finally:
        h.stop()
