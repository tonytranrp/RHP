"""The client's codec, frames, handshake derivations and signatures against golden vectors. The same
bytes are checked by RHP's C++ suite (Tests/unit/wire/cross_language_tests.cpp), so both ends are
pinned to one wire format."""

import json
import os

import pytest

from rhp_client import _ed25519, _msgpack as msgpack
from rhp_client._frame import (FLAG_CRC_OMITTED, FLAG_MAC, FrameDecoder, Op, PROTOCOL_REVISION, crc32c, encode_frame, mac32)
from rhp_client._session import _derive, _transcript
from rhp_client.identity import SCRIPT_DOMAIN, Identity, sign_script

VECTORS = json.load(open(os.path.join(os.path.dirname(__file__), "vectors.json"), encoding="utf-8"))
INPUTS = VECTORS["inputs"]
PSK = bytes.fromhex(INPUTS["psk"])
NC = bytes.fromhex(INPUTS["client_nonce"])
NH = bytes.fromhex(INPUTS["host_nonce"])
BINDING = bytes.fromhex(INPUTS["binding"])
SEED = bytes.fromhex(INPUTS["ed25519_seed"])


def frame_hex(title):
    return VECTORS["frames"][title]


# ---- msgpack -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("value, encoded", [
    (None, "c0"), (True, "c3"), (False, "c2"), (0, "00"), (127, "7f"), (128, "cc80"), (255, "ccff"), (256, "cd0100"),
    (65536, "ce00010000"), (2**32, "cf0000000100000000"), (-1, "ff"), (-32, "e0"), (-33, "d0df"), (-129, "d1ff7f"),
    (-32769, "d2ffff7fff"), (-(2**31) - 1, "d3ffffffff7fffffff"), (1.5, "cb3ff8000000000000"), ("", "a0"), ("abc", "a3616263"),
    (b"\x01\x02", "c4020102"), ([], "90"), ([1, "a"], "9201a161"), ({"a": 1}, "81a16101"),
])
def test_msgpack_canonical_forms(value, encoded):
    assert msgpack.encode(value).hex() == encoded
    assert msgpack.decode(bytes.fromhex(encoded)) == value


def test_msgpack_lengths_switch_forms():
    assert msgpack.encode("x" * 31)[0] == 0xBF
    assert msgpack.encode("x" * 32)[:2] == b"\xd9\x20"
    assert msgpack.encode("x" * 256)[:3] == b"\xda\x01\x00"
    assert msgpack.encode(list(range(16)))[:3] == b"\xdc\x00\x10"
    assert msgpack.encode({str(i): i for i in range(16)})[:3] == b"\xde\x00\x10"
    for value in ("x" * 70000, b"y" * 70000, list(range(70000))):
        assert msgpack.decode(msgpack.encode(value)) == value


def test_msgpack_rhp_specifics():
    # RHP integers are signed 64-bit: a larger uint64 decodes as a number, and won't encode.
    assert msgpack.decode(bytes.fromhex("cfffffffffffffffff")) == float(2**64 - 1)
    with pytest.raises(OverflowError):
        msgpack.encode(2**63)
    # Maps keep their order; repeated or unhashable keys come back as Map.
    pairs = msgpack.decode(bytes.fromhex("82a161 01 a161 02".replace(" ", "")))
    assert isinstance(pairs, msgpack.Map) and list(pairs) == [("a", 1), ("a", 2)]
    assert msgpack.decode(msgpack.encode(msgpack.Map([([1], 2)]))) == msgpack.Map([([1], 2)])
    assert msgpack.decode(bytes.fromhex("ca3fc00000")) == 1.5  # float32 is read


@pytest.mark.parametrize("data, why", [
    ("", "truncated"), ("a3 6162", "truncated"), ("c1", "0xc1"), ("d4 01 02", "extension"), ("01 02", "trailing"),
    ("dd 7fffffff", "truncated"),
])
def test_msgpack_rejects(data, why):
    with pytest.raises(msgpack.MessagePackError, match=why):
        msgpack.decode(bytes.fromhex(data.replace(" ", "")))


def test_msgpack_limits():
    deep = b"\x91" * 101 + b"\xc0"
    with pytest.raises(msgpack.MessagePackError, match="deeper"):
        msgpack.decode(deep)
    assert msgpack.decode(b"\x91" * 100 + b"\xc0") is not None
    with pytest.raises(msgpack.MessagePackError, match="values"):
        msgpack.decode(msgpack.encode(list(range(50))), max_elements=10)


# ---- frames ----------------------------------------------------------------------------------------------

def test_crc32c_check_values():
    assert crc32c(b"123456789") == 0xE3069283
    assert crc32c(b"") == 0
    assert crc32c(bytes(32)) == 0x8A9136AA
    assert crc32c(b"\xff" * 32) == 0x62A8AB43
    assert crc32c(b"6789", crc32c(b"12345")) == 0xE3069283


def test_handshake_derivations_match_vectors():
    for label, binding in (("plaintext", b""), ("TLS binding 60..7f", BINDING)):
        expected = VECTORS["transcripts"][label]
        t = _transcript(INPUTS["name"], NC, NH, binding)
        assert t.hex() == expected["T"]
        for key in ("rhp/host", "rhp/client", "rhp/c2h", "rhp/h2c"):
            assert _derive(PSK, key, t).hex() == expected[key], (label, key)


def keys():
    t = _transcript(INPUTS["name"], NC, NH, b"")
    return {name: _derive(PSK, name, t) for name in ("rhp/host", "rhp/client", "rhp/c2h", "rhp/h2c")}


def test_frames_match_vectors():
    k = keys()
    hello = {"rev": 4, "platform": "python", "auth": {"key": "dev", "nonce": NC}}
    assert encode_frame(Op.HELLO, 0, 0, msgpack.encode(hello)).hex() == frame_hex("hello (client, plaintext)")
    challenge = {"rev": 4, "platform": "windows", "auth": {"nonce": NH, "proof": k["rhp/host"]}}
    assert encode_frame(Op.CHALLENGE, 0, 0, msgpack.encode(challenge)).hex() == frame_hex("challenge (host)")
    assert encode_frame(Op.RESPONSE, 0, 0, msgpack.encode({"auth": {"proof": k["rhp/client"]}})).hex() == frame_hex("response (client)")
    welcome = {"session": 1, "identity": "dev", "role": "admin", "heartbeat_ms": 2000, "platform": "windows"}
    assert encode_frame(Op.WELCOME, 0, 0, msgpack.encode(welcome), k["rhp/h2c"]).hex() == frame_hex("welcome (host, sealed h2c)")
    signature = _ed25519.sign(SEED, SCRIPT_DOMAIN + b"return 1")
    assert signature.hex() == VECTORS["script_signature_rfc8032_test1"]
    request = {"req": 1, "idem": 0x0123456789ABCDEF, "body": {"source": "return 1", "chunk": "exec", "signature": {"signer": "dev", "sig": signature}}}
    assert encode_frame(Op.EXEC, 1, 0, msgpack.encode(request), k["rhp/c2h"]).hex() == frame_hex("exec request seq 1 ack 0 (client, sealed c2h)")
    reply = encode_frame(Op.RESULT, 1, 1, msgpack.encode({"req": 1, "body": [1]}), k["rhp/h2c"])
    assert reply.hex() == frame_hex("result reply seq 1 ack 1 (host, sealed h2c): body [1]")
    assert encode_frame(Op.ACK, 1, 1, b"", k["rhp/c2h"]).hex() == frame_hex("ack control seq 1 ack 1 (client, sealed c2h)")
    assert encode_frame(Op.ACK, 1, 1, b"", k["rhp/c2h"], crc=False).hex() == frame_hex("same ack on a TLS link (kCrcOmitted, no CRC)")
    proof = mac32(k["rhp/c2h"], b"rhp/resume")
    assert proof.hex() == VECTORS["resume_proof"]
    assert mac32(k["rhp/h2c"], b"rhp/resumed").hex() == VECTORS["resumed_proof"]
    resume = encode_frame(Op.RESUME, 2, 1, msgpack.encode({"session": 1, "proof": proof}), k["rhp/c2h"])
    assert resume.hex() == frame_hex("kResume (client, control seq 2, ack 1, sealed c2h)")


def test_frame_decoder():
    k = keys()
    raw = bytes.fromhex(frame_hex("result reply seq 1 ack 1 (host, sealed h2c): body [1]"))
    decoder = FrameDecoder(1024)
    decoder.feed(b"junk" + raw[:10])
    assert decoder.next().status == "bad_magic"
    assert decoder.next() is None
    decoder.feed(raw[10:])
    frame = decoder.next()
    assert frame.status == "frame" and frame.op == Op.RESULT and frame.seq == 1 and frame.ack == 1 and frame.flags & FLAG_MAC
    assert mac32(k["rhp/h2c"], frame.sealed) == frame.mac
    assert msgpack.decode(frame.payload) == {"req": 1, "body": [1]}
    # A flipped payload byte fails the CRC; a frame over the limit poisons the stream.
    bad = bytearray(raw)
    bad[30] ^= 1
    decoder.feed(bytes(bad))
    assert decoder.next().status == "bad_crc"
    small = FrameDecoder(4)
    small.feed(raw)
    assert small.next().status == "too_large"
    other = bytearray(encode_frame(Op.PING, 1, 0, b""))
    other[4] = PROTOCOL_REVISION + 1
    other = encode_frame(Op.PING, 1, 0, b"", revision=PROTOCOL_REVISION + 1)
    decoder.feed(other)
    assert decoder.next().status == "bad_revision"
    tls_ack = bytes.fromhex(frame_hex("same ack on a TLS link (kCrcOmitted, no CRC)"))
    decoder.feed(tls_ack)
    frame = decoder.next()
    assert frame.status == "frame" and frame.flags & FLAG_CRC_OMITTED and len(frame.mac) == 32


# ---- Ed25519 and identities ---------------------------------------------------------------------------

RFC8032 = [  # (seed, public key, message, signature) - RFC 8032 section 7.1, tests 1-3
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("seed, public, message, signature", RFC8032)
def test_ed25519_rfc8032(seed, public, message, signature):
    seed, public, message, signature = (bytes.fromhex(x) for x in (seed, public, message, signature))
    assert _ed25519.public_key(seed) == public
    assert _ed25519.sign(seed, message) == signature
    assert _ed25519.verify(public, message, signature)
    assert not _ed25519.verify(public, message + b"x", signature)


def test_identity_file_and_script_signature():
    import base64
    text = '# a comment\nname = "dev"\npsk = "%s"\nsigning_key = "%s"\n' % (base64.b64encode(PSK).decode(), base64.b64encode(SEED).decode())
    me = Identity.parse(text)
    assert me.name == "dev" and me.signer == "dev" and me.psk == PSK
    assert "psk" not in repr(me) or PSK.hex() not in repr(me)
    signed = sign_script(me, "return 1")
    assert signed == {"signer": "dev", "sig": bytes.fromhex(VECTORS["script_signature_rfc8032_test1"])}
    assert me.public_key() == bytes.fromhex(RFC8032[0][1])
    assert sign_script(Identity("obs", PSK), "return 1") is None
    for bad in ('name = dev\npsk = "x"', 'name = "dev"', 'name = "dev"\npsk = "AAAA"', 'name = "dev"\npsk = "not base64!"'):
        with pytest.raises(Exception):
            Identity.parse(bad)
