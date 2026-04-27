"""
Cryptographic Engine for the Double Ratchet Protocol.

Implements:
- X25519 Diffie-Hellman key exchange (Asymmetric Ratchet)
- HKDF-SHA256 (Symmetric KDF Ratchet)
- AES-256-GCM (AEAD encryption)
- Hybrid Key Setup: Real CRYSTALS-Kyber-768 (ML-KEM-768) via liboqs + ECC fallback

References:
- Signal Protocol Double Ratchet Specification
- NIST SP 800-56C Rev. 2 (KDF)
- NIST FIPS 203 (ML-KEM / CRYSTALS-Kyber)
"""

import os
import json
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple, Dict

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization

# ---------------------------------------------------------------------------
# Attempt to load real PQC via liboqs
# ---------------------------------------------------------------------------
OQS_AVAILABLE = False
try:
    import oqs
    # Quick smoke test
    _test_kem = oqs.KeyEncapsulation("ML-KEM-768")
    _test_pk = _test_kem.generate_keypair()
    _test_kem.free()
    del _test_kem, _test_pk
    OQS_AVAILABLE = True
except Exception:
    pass

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _pub_bytes(pub: X25519PublicKey) -> bytes:
    """Serialize an X25519 public key to raw 32-byte form."""
    return pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _priv_bytes(priv: X25519PrivateKey) -> bytes:
    """Serialize an X25519 private key to raw 32-byte form."""
    return priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def hex_short(data: bytes, n: int = 8) -> str:
    """Return a short hex preview of *data*."""
    return data.hex()[:n] + "…"


# ---------------------------------------------------------------------------
# PQC KEM Abstraction (Dual-Track)
# ---------------------------------------------------------------------------

class KyberKEM:
    """
    Dual-track KEM: uses real ML-KEM-768 via liboqs when available,
    falls back to a size-accurate simulation otherwise.
    The ECC component is never affected by PQC failures.
    """

    # ML-KEM-768 sizes per FIPS 203
    PK_SIZE = 1184
    SK_SIZE = 2400
    CT_SIZE = 1088
    SS_SIZE = 32

    @staticmethod
    def is_real() -> bool:
        return OQS_AVAILABLE

    @staticmethod
    def keygen() -> Tuple[bytes, bytes, dict]:
        """Generate keypair. Returns (public_key, secret_key, timing_meta)."""
        t0 = time.perf_counter()
        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            kem.free()
        else:
            pk = os.urandom(KyberKEM.PK_SIZE)
            sk = os.urandom(KyberKEM.SK_SIZE)
        elapsed = (time.perf_counter() - t0) * 1000
        return pk, sk, {"keygen_ms": round(elapsed, 4)}

    @staticmethod
    def encapsulate(pk: bytes) -> Tuple[bytes, bytes, dict]:
        """Encapsulate. Returns (ciphertext, shared_secret, timing_meta)."""
        t0 = time.perf_counter()
        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            ct, ss = kem.encap_secret(pk)
            kem.free()
        else:
            ct = os.urandom(KyberKEM.CT_SIZE)
            ss = os.urandom(KyberKEM.SS_SIZE)
        elapsed = (time.perf_counter() - t0) * 1000
        return ct, ss, {"encaps_ms": round(elapsed, 4)}

    @staticmethod
    def decapsulate(sk: bytes, ct: bytes) -> Tuple[bytes, dict]:
        """Decapsulate. Returns (shared_secret, timing_meta)."""
        t0 = time.perf_counter()
        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key=sk)
            ss = kem.decap_secret(ct)
            kem.free()
        else:
            ss = os.urandom(KyberKEM.SS_SIZE)
        elapsed = (time.perf_counter() - t0) * 1000
        return ss, {"decaps_ms": round(elapsed, 4)}


# ---------------------------------------------------------------------------
# Hybrid Key Setup (PQC + ECC)
# ---------------------------------------------------------------------------

class HybridKeySetup:
    """
    Hybrid PQC + ECC initial key agreement.

    Dual-track architecture: a failure in PQC never compromises
    the ECC (X25519) component. If PQC fails, ECC alone is used.
    """

    @staticmethod
    def perform() -> Tuple[bytes, dict]:
        """Return (shared_root_key, metadata_dict)."""
        timing = {}

        # --- ECC component (always real) ---
        t0 = time.perf_counter()
        alice_id = X25519PrivateKey.generate()
        bob_id = X25519PrivateKey.generate()
        ecc_shared = alice_id.exchange(bob_id.public_key())
        timing["ecc_ms"] = round((time.perf_counter() - t0) * 1000, 4)

        # --- PQC component (dual-track) ---
        pqc_ok = False
        pqc_shared = os.urandom(32)  # fallback
        pqc_meta = {}
        try:
            pk, sk, kg_t = KyberKEM.keygen()
            ct, ss_enc, enc_t = KyberKEM.encapsulate(pk)
            if KyberKEM.is_real():
                ss_dec, dec_t = KyberKEM.decapsulate(sk, ct)
                assert ss_enc == ss_dec, "KEM decapsulation mismatch"
                pqc_shared = ss_enc
            else:
                dec_t = {"decaps_ms": 0.0}
                pqc_shared = ss_enc
            pqc_ok = True
            pqc_meta = {**kg_t, **enc_t, **dec_t}
            timing.update(pqc_meta)
        except Exception as e:
            pqc_meta = {"pqc_error": str(e)}

        # --- Combine via HKDF ---
        t0 = time.perf_counter()
        combined = ecc_shared + pqc_shared
        root_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"hybrid-handshake-salt",
            info=b"double-ratchet-init",
        ).derive(combined)
        timing["hkdf_ms"] = round((time.perf_counter() - t0) * 1000, 4)

        kem_label = "ML-KEM-768" if KyberKEM.is_real() else "ML-KEM-768 (simulated)"

        meta = {
            "ecc_alice_pub": _pub_bytes(alice_id.public_key()).hex(),
            "ecc_bob_pub": _pub_bytes(bob_id.public_key()).hex(),
            "pqc_kem": kem_label,
            "pqc_real": KyberKEM.is_real(),
            "pqc_ok": pqc_ok,
            "ecc_shared_hex": ecc_shared.hex()[:16] + "…",
            "pqc_shared_hex": pqc_shared.hex()[:16] + "…",
            "root_key_hex": root_key.hex(),
            "kyber_pk_bytes": KyberKEM.PK_SIZE,
            "kyber_ct_bytes": KyberKEM.CT_SIZE,
            "timing": timing,
        }
        return root_key, meta

    @staticmethod
    def perform_classical() -> Tuple[bytes, dict]:
        """Pure X25519-only handshake for benchmarking comparison."""
        timing = {}
        t0 = time.perf_counter()
        alice_id = X25519PrivateKey.generate()
        bob_id = X25519PrivateKey.generate()
        ecc_shared = alice_id.exchange(bob_id.public_key())
        timing["ecc_ms"] = round((time.perf_counter() - t0) * 1000, 4)

        t0 = time.perf_counter()
        root_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"classical-handshake-salt",
            info=b"double-ratchet-init",
        ).derive(ecc_shared)
        timing["hkdf_ms"] = round((time.perf_counter() - t0) * 1000, 4)

        meta = {
            "ecc_alice_pub": _pub_bytes(alice_id.public_key()).hex(),
            "ecc_bob_pub": _pub_bytes(bob_id.public_key()).hex(),
            "pqc_kem": "None (classical only)",
            "pqc_real": False,
            "root_key_hex": root_key.hex(),
            "timing": timing,
            "payload_bytes": 32,  # just X25519 pub key
        }
        return root_key, meta


# ---------------------------------------------------------------------------
# KDF Chain helpers
# ---------------------------------------------------------------------------

def kdf_rk(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """Root-key KDF: derive new (root_key, chain_key) from shared DH output."""
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=b"ratchet-root-kdf",
    ).derive(dh_out)
    return derived[:32], derived[32:]


def kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    """Chain-key KDF: advance chain → (new_chain_key, message_key)."""
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=ck,
        info=b"ratchet-chain-kdf",
    ).derive(b"\x01")
    return derived[:32], derived[32:]


# ---------------------------------------------------------------------------
# AEAD encrypt / decrypt (AES-256-GCM)
# ---------------------------------------------------------------------------

def aead_encrypt(key: bytes, plaintext: bytes, ad: bytes) -> Tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM.  Returns (nonce, ciphertext+tag)."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, ad)
    return nonce, ct


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    """Decrypt with AES-256-GCM.  Raises on failure."""
    return AESGCM(key).decrypt(nonce, ciphertext, ad)


# ---------------------------------------------------------------------------
# Double Ratchet State
# ---------------------------------------------------------------------------

MAX_SKIP = 100  # max skipped message keys to store

@dataclass
class RatchetState:
    """Mutable state for one side of a Double Ratchet session."""

    # Identity
    name: str

    # Root key
    root_key: bytes

    # Our current DH ratchet key-pair
    dh_priv: X25519PrivateKey
    dh_pub: X25519PublicKey  # cached public half

    # The remote party's current public DH key (may be None initially)
    remote_dh_pub: Optional[X25519PublicKey] = None

    # Sending / receiving chain keys
    send_chain_key: Optional[bytes] = None
    recv_chain_key: Optional[bytes] = None

    # Message counters
    send_msg_no: int = 0
    recv_msg_no: int = 0

    # Number of DH ratchet steps performed
    ratchet_step: int = 0

    # Skipped message keys: {(dh_pub_hex, msg_no): message_key}
    skipped_keys: Dict[Tuple[str, int], bytes] = field(default_factory=dict)

    def rotate_dh(self) -> None:
        """Generate a fresh DH key-pair (asymmetric ratchet step)."""
        self.dh_priv = X25519PrivateKey.generate()
        self.dh_pub = self.dh_priv.public_key()

    def skip_message_keys(self, until: int) -> None:
        """Pre-derive and store message keys for skipped messages."""
        if self.recv_chain_key is None:
            return
        while self.recv_msg_no < until and len(self.skipped_keys) < MAX_SKIP:
            self.recv_chain_key, mk = kdf_ck(self.recv_chain_key)
            pub_hex = _pub_bytes(self.remote_dh_pub).hex() if self.remote_dh_pub else ""
            self.skipped_keys[(pub_hex, self.recv_msg_no)] = mk
            self.recv_msg_no += 1

    def try_skipped_key(self, dh_pub_hex: str, msg_no: int) -> Optional[bytes]:
        """Try to retrieve a skipped message key."""
        key = (dh_pub_hex, msg_no)
        return self.skipped_keys.pop(key, None)

    def snapshot(self) -> dict:
        """Return a JSON-safe snapshot of the cryptographic state."""
        return {
            "name": self.name,
            "root_key": self.root_key.hex(),
            "dh_pub": _pub_bytes(self.dh_pub).hex(),
            "dh_priv": _priv_bytes(self.dh_priv).hex(),
            "remote_dh_pub": _pub_bytes(self.remote_dh_pub).hex() if self.remote_dh_pub else None,
            "send_chain_key": self.send_chain_key.hex() if self.send_chain_key else None,
            "recv_chain_key": self.recv_chain_key.hex() if self.recv_chain_key else None,
            "send_msg_no": self.send_msg_no,
            "recv_msg_no": self.recv_msg_no,
            "ratchet_step": self.ratchet_step,
            "skipped_keys_count": len(self.skipped_keys),
        }


# ---------------------------------------------------------------------------
# Double Ratchet Protocol
# ---------------------------------------------------------------------------

class DoubleRatchet:
    """
    Manages a full Double Ratchet session between two parties.

    After construction the instance holds the states for Alice AND Bob
    so that the Flask backend can drive both sides from a single object.
    """

    def __init__(self) -> None:
        # Perform hybrid key setup
        root_key, self.setup_meta = HybridKeySetup.perform()

        # Generate initial DH ratchet key-pairs
        alice_dh = X25519PrivateKey.generate()
        bob_dh = X25519PrivateKey.generate()

        # Exchange public keys
        alice_pub = alice_dh.public_key()
        bob_pub = bob_dh.public_key()

        # Derive initial chain keys from root key + first DH
        dh_out_ab = alice_dh.exchange(bob_pub)
        new_rk, alice_send_ck = kdf_rk(root_key, dh_out_ab)

        dh_out_ba = bob_dh.exchange(alice_pub)
        _, bob_recv_ck = kdf_rk(root_key, dh_out_ba)

        # Bob also needs a send chain – perform one ratchet step
        bob_dh2 = X25519PrivateKey.generate()
        dh_out_bob_send = bob_dh2.exchange(alice_pub)
        new_rk2, bob_send_ck = kdf_rk(new_rk, dh_out_bob_send)

        self.alice = RatchetState(
            name="Alice",
            root_key=new_rk,
            dh_priv=alice_dh,
            dh_pub=alice_pub,
            remote_dh_pub=bob_pub,
            send_chain_key=alice_send_ck,
            recv_chain_key=None,
            ratchet_step=1,
        )

        self.bob = RatchetState(
            name="Bob",
            root_key=new_rk2,
            dh_priv=bob_dh2,
            dh_pub=bob_dh2.public_key(),
            remote_dh_pub=alice_pub,
            send_chain_key=bob_send_ck,
            recv_chain_key=bob_recv_ck,
            ratchet_step=1,
        )

        # Event log (for UI timeline)
        self.log: list[dict] = []

    # ---- sending -----------------------------------------------------------

    def send(self, sender_name: str, plaintext: str) -> dict:
        """
        Encrypt a message from *sender_name* ("Alice" or "Bob").

        Returns a dict with ciphertext metadata and ratchet diagnostics.
        """
        sender = self._party(sender_name)

        # Advance sending chain
        sender.send_chain_key, msg_key = kdf_ck(sender.send_chain_key)

        # Build associated data (header)
        header = {
            "dh_pub": _pub_bytes(sender.dh_pub).hex(),
            "msg_no": sender.send_msg_no,
            "ratchet_step": sender.ratchet_step,
        }
        ad = json.dumps(header, sort_keys=True).encode()

        nonce, ct = aead_encrypt(msg_key, plaintext.encode(), ad)

        sender.send_msg_no += 1

        envelope = {
            "sender": sender_name,
            "header": header,
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ct.hex(),
            "ad_hex": ad.hex(),
            "msg_key_hex": msg_key.hex(),
        }

        self.log.append({
            "event": "send",
            "sender": sender_name,
            "ratchet_step": sender.ratchet_step,
            "plaintext": plaintext,
            "ciphertext_short": ct.hex()[:32] + "…",
        })

        return envelope

    # ---- receiving ---------------------------------------------------------

    def receive(self, receiver_name: str, envelope: dict) -> dict:
        """
        Decrypt an envelope for *receiver_name*.

        If the sender's DH public key differs from what we have stored
        we perform a DH ratchet step first (this is the asymmetric
        ratchet that provides future secrecy / healing).
        """
        receiver = self._party(receiver_name)

        sender_dh_pub_bytes = bytes.fromhex(envelope["header"]["dh_pub"])
        sender_dh_pub = X25519PublicKey.from_public_bytes(sender_dh_pub_bytes)
        msg_no = envelope["header"]["msg_no"]

        # Check for skipped message key first
        skipped_mk = receiver.try_skipped_key(
            sender_dh_pub_bytes.hex(), msg_no
        )

        if skipped_mk:
            nonce = bytes.fromhex(envelope["nonce_hex"])
            ct = bytes.fromhex(envelope["ciphertext_hex"])
            ad = bytes.fromhex(envelope["ad_hex"])
            plaintext = aead_decrypt(skipped_mk, nonce, ct, ad).decode()
            self.log.append({
                "event": "receive",
                "receiver": receiver_name,
                "ratchet_step": receiver.ratchet_step,
                "plaintext": plaintext,
                "ratcheted": False,
                "skipped_key_used": True,
            })
            return {
                "plaintext": plaintext,
                "ratcheted": False,
                "ratchet_step": receiver.ratchet_step,
                "msg_key_hex": skipped_mk.hex(),
                "skipped_key_used": True,
            }

        stored_pub = (
            _pub_bytes(receiver.remote_dh_pub) if receiver.remote_dh_pub else None
        )

        ratcheted = False
        if stored_pub is None or sender_dh_pub_bytes != stored_pub:
            # Skip any remaining message keys from the old chain
            if receiver.recv_chain_key is not None:
                receiver.skip_message_keys(msg_no)

            # --- DH ratchet step (provides future secrecy) ---
            receiver.remote_dh_pub = sender_dh_pub
            dh_out = receiver.dh_priv.exchange(sender_dh_pub)
            receiver.root_key, receiver.recv_chain_key = kdf_rk(
                receiver.root_key, dh_out
            )
            receiver.recv_msg_no = 0

            # Also rotate our own DH pair and derive a new send chain
            receiver.rotate_dh()
            dh_out2 = receiver.dh_priv.exchange(sender_dh_pub)
            receiver.root_key, receiver.send_chain_key = kdf_rk(
                receiver.root_key, dh_out2
            )
            receiver.send_msg_no = 0
            receiver.ratchet_step += 1
            ratcheted = True

        # Skip message keys if msg_no > recv_msg_no
        if msg_no > receiver.recv_msg_no:
            receiver.skip_message_keys(msg_no)

        # Advance receiving chain
        receiver.recv_chain_key, msg_key = kdf_ck(receiver.recv_chain_key)

        nonce = bytes.fromhex(envelope["nonce_hex"])
        ct = bytes.fromhex(envelope["ciphertext_hex"])
        ad = bytes.fromhex(envelope["ad_hex"])

        plaintext = aead_decrypt(msg_key, nonce, ct, ad).decode()

        receiver.recv_msg_no += 1

        self.log.append({
            "event": "receive",
            "receiver": receiver_name,
            "ratchet_step": receiver.ratchet_step,
            "plaintext": plaintext,
            "ratcheted": ratcheted,
        })

        return {
            "plaintext": plaintext,
            "ratcheted": ratcheted,
            "ratchet_step": receiver.ratchet_step,
            "msg_key_hex": msg_key.hex(),
            "skipped_key_used": False,
        }

    # ---- compromise --------------------------------------------------------

    def compromise(self, target: str) -> dict:
        """
        Simulate a full state-compromise of *target*.

        Returns a snapshot of the target's current cryptographic state
        that an adversary would obtain.
        """
        party = self._party(target)
        snapshot = party.snapshot()

        self.log.append({
            "event": "compromise",
            "target": target,
            "ratchet_step": party.ratchet_step,
        })

        return snapshot

    def try_adversary_decrypt(self, compromised_state: dict, envelope: dict) -> dict:
        """
        Attempt to decrypt *envelope* using a previously captured state.
        """
        try:
            rk = bytes.fromhex(compromised_state["root_key"])
            dh_priv = X25519PrivateKey.from_private_bytes(
                bytes.fromhex(compromised_state["dh_priv"])
            )

            sender_dh_pub_bytes = bytes.fromhex(envelope["header"]["dh_pub"])
            sender_dh_pub = X25519PublicKey.from_public_bytes(sender_dh_pub_bytes)

            dh_out = dh_priv.exchange(sender_dh_pub)
            _, recv_ck = kdf_rk(rk, dh_out)
            _, msg_key = kdf_ck(recv_ck)

            nonce = bytes.fromhex(envelope["nonce_hex"])
            ct = bytes.fromhex(envelope["ciphertext_hex"])
            ad = bytes.fromhex(envelope["ad_hex"])

            plaintext = aead_decrypt(msg_key, nonce, ct, ad).decode()

            self.log.append({
                "event": "adversary_decrypt",
                "success": True,
                "plaintext": plaintext,
            })

            return {"success": True, "plaintext": plaintext}

        except Exception as e:
            self.log.append({
                "event": "adversary_decrypt",
                "success": False,
                "error": str(e),
            })
            return {
                "success": False,
                "error": f"Decryption FAILED — {type(e).__name__}: {e}",
            }

    # ---- helpers -----------------------------------------------------------

    def _party(self, name: str) -> RatchetState:
        if name == "Alice":
            return self.alice
        if name == "Bob":
            return self.bob
        raise ValueError(f"Unknown party: {name}")

    def _other(self, name: str) -> RatchetState:
        return self._party("Bob" if name == "Alice" else "Alice")


# ---------------------------------------------------------------------------
# Benchmarking utilities
# ---------------------------------------------------------------------------

def run_benchmark(n_iterations: int = 10) -> dict:
    """Run N handshakes for both classical and hybrid, collecting metrics."""
    classical_results = []
    hybrid_results = []

    for _ in range(n_iterations):
        # Classical (X25519 only)
        t0 = time.perf_counter()
        _, c_meta = HybridKeySetup.perform_classical()
        c_total = (time.perf_counter() - t0) * 1000
        classical_results.append({
            "total_ms": round(c_total, 4),
            "payload_bytes": 32,
            **c_meta["timing"],
        })

        # Hybrid (X25519 + Kyber)
        t0 = time.perf_counter()
        _, h_meta = HybridKeySetup.perform()
        h_total = (time.perf_counter() - t0) * 1000
        hybrid_results.append({
            "total_ms": round(h_total, 4),
            "payload_bytes": 32 + KyberKEM.PK_SIZE + KyberKEM.CT_SIZE,
            **h_meta["timing"],
        })

    avg_classical_ms = sum(r["total_ms"] for r in classical_results) / n_iterations
    avg_hybrid_ms = sum(r["total_ms"] for r in hybrid_results) / n_iterations

    return {
        "n": n_iterations,
        "pqc_real": KyberKEM.is_real(),
        "classical": classical_results,
        "hybrid": hybrid_results,
        "avg_classical_ms": round(avg_classical_ms, 4),
        "avg_hybrid_ms": round(avg_hybrid_ms, 4),
        "classical_payload_bytes": 32,
        "hybrid_payload_bytes": 32 + KyberKEM.PK_SIZE + KyberKEM.CT_SIZE,
    }


def benchmark_handshake() -> dict:
    """
    Perform a single hybrid handshake and return benchmark metrics.

    Returns a dict with:
      - execution_time_ms : float — total handshake wall-clock time in milliseconds
      - ciphertext_size_bytes : int — PQC KEM ciphertext size in bytes
      - pqc_real : bool — whether real ML-KEM-768 via liboqs was used
      - breakdown : dict — per-phase timings (ecc_ms, keygen_ms, encaps_ms, decaps_ms, hkdf_ms)
    """
    t0 = time.perf_counter()
    root_key, meta = HybridKeySetup.perform()
    elapsed_ms = (time.perf_counter() - t0) * 1000

    return {
        "execution_time_ms": round(elapsed_ms, 4),
        "ciphertext_size_bytes": KyberKEM.CT_SIZE,
        "pqc_real": KyberKEM.is_real(),
        "pqc_kem": meta.get("pqc_kem", "unknown"),
        "root_key_hex": root_key.hex(),
        "breakdown": meta.get("timing", {}),
    }
