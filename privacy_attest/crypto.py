"""Hashing, Merkle trees, DSSE envelopes and Ed25519 signing.

Nothing here is novel: in-toto statements wrapped in DSSE envelopes are the
standard format used for software supply-chain attestations. A production
version would sign with Sigstore so keys are tied to a verified identity.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------- Merkle tree
#
# Leaves and inner nodes are hashed with different prefixes (as in RFC 6962), so
# an inner node can never be passed off as a leaf. An odd node at the end of a
# level is carried up unchanged rather than duplicated.

def leaf_hash(data: str) -> str:
    return sha256_hex(b"\x00" + data.encode("utf-8"))


def _pair(a: str, b: str) -> str:
    return sha256_hex(b"\x01" + bytes.fromhex(a) + bytes.fromhex(b))


def _next_level(level: list[str]) -> list[str]:
    nxt = [_pair(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
    if len(level) % 2:
        nxt.append(level[-1])
    return nxt


def merkle_root(leaves: list[str]) -> str:
    """Root over hex leaf hashes. Empty list -> hash of empty string."""
    if not leaves:
        return sha256_hex(b"")
    level = list(leaves)
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[dict]:
    """Sibling path from leaf to root: [{"hash":..., "side":"left"|"right"}]."""
    proof = []
    level = list(leaves)
    i = index
    while len(level) > 1:
        sib = i ^ 1
        if sib < len(level):
            proof.append({"hash": level[sib], "side": "left" if sib < i else "right"})
        level = _next_level(level)
        i //= 2
    return proof


def verify_merkle_proof(leaf: str, proof: list[dict], root: str) -> bool:
    h = leaf
    for step in proof:
        h = _pair(step["hash"], h) if step["side"] == "left" else _pair(h, step["hash"])
    return h == root


# ---------------------------------------------------------------- Keys

def generate_keypair(private_path: Path, public_path: Path) -> str:
    key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_path.write_bytes(pub)
    return keyid(pub)


def keyid(public_pem: bytes) -> str:
    return "sha256:" + sha256_hex(public_pem)[:16]


def load_private(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public(path: Path) -> tuple[Ed25519PublicKey, str]:
    pem = path.read_bytes()
    return serialization.load_pem_public_key(pem), keyid(pem)


# ---------------------------------------------------------------- DSSE

def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def dsse_sign(payload_type: str, payload: bytes, key: Ed25519PrivateKey, kid: str) -> dict:
    sig = key.sign(pae(payload_type, payload))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": kid, "sig": base64.b64encode(sig).decode()}],
    }


def dsse_verify(envelope: dict, pub: Ed25519PublicKey, kid: str) -> bytes:
    """Return the payload bytes if a signature from this key verifies, else raise."""
    payload = base64.b64decode(envelope["payload"])
    for s in envelope.get("signatures", []):
        if s.get("keyid") != kid:
            continue
        try:
            pub.verify(base64.b64decode(s["sig"]), pae(envelope["payloadType"], payload))
            return payload
        except InvalidSignature:
            break
    raise ValueError("no valid signature from the registered member key")
