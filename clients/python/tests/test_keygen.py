"""python -m rhp_client keygen: an owner-only identity file, patch by default, the pre-shared key kept
off the terminal unless asked for."""

import base64
import os
import stat

from rhp_client.__main__ import main
from rhp_client.identity import Identity


def test_keygen_writes_a_private_file_and_keeps_the_secret_in_it(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["keygen", "dev"]) == 0
    out = capsys.readouterr()
    identity = Identity.load("dev.rhpid")
    psk = base64.b64encode(identity.psk).decode()
    assert psk not in out.out
    assert "keyring file:  dev patch <psk from dev.rhpid>" in out.out
    assert "signers file:  dev %s" % base64.b64encode(identity.public_key()).decode() in out.out
    assert out.err == ""
    if os.name == "posix":  # on Windows the mode is only the read-only flag
        assert stat.S_IMODE(os.stat("dev.rhpid").st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["dev.rhpid"]  # no temporary left behind

    # Never overwrites (1); usage errors are 2.
    assert main(["keygen", "dev"]) == 1
    assert Identity.load("dev.rhpid").psk == identity.psk
    assert main(["keygen"]) == 2
    assert main(["keygen", "x", "--role", "root"]) == 2
    assert not os.path.exists("x.rhpid")


def test_keygen_prints_the_secret_and_admin_only_when_asked(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["keygen", "lead", "--role", "admin", "--show-secret"]) == 0
    out = capsys.readouterr()
    psk = base64.b64encode(Identity.load("lead.rhpid").psk).decode()
    assert "keyring file:  lead admin %s" % psk in out.out
    assert out.err.startswith("warning: an admin identity")
