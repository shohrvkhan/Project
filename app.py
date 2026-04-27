"""
Flask backend for the Double Ratchet Trap-Resilient Communication Demo.

Endpoints:
  GET  /                → Serve the main UI
  GET  /api/init        → Initialize a fresh Double Ratchet session
  POST /api/send        → Encrypt & send a message
  POST /api/compromise  → Compromise a party's state
  POST /api/intercept   → Adversary attempts decryption with stale state
  GET  /api/state       → Return current ratchet state for both parties
  GET  /api/log         → Return event timeline
  POST /api/benchmark   → Run N handshakes and return timing data
  POST /api/mitm_tamper → Flip a bit in ciphertext and attempt decryption
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from crypto_engine import (
    DoubleRatchet, kdf_rk, kdf_ck, aead_decrypt, aead_encrypt,
    run_benchmark, benchmark_handshake, KyberKEM, OQS_AVAILABLE,
)
import os

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)

# ---------------------------------------------------------------------------
# In-memory session state
# ---------------------------------------------------------------------------
session: dict = {
    "ratchet": None,
    "compromised_state": None,
    "pending_envelope": None,
    "envelopes": [],
}


def _init_session():
    """Create a fresh Double Ratchet session."""
    session["ratchet"] = DoubleRatchet()
    session["compromised_state"] = None
    session["pending_envelope"] = None
    session["envelopes"] = []
    for key in ("adv_recv_ck", "adv_send_ck", "adv_root_key", "adv_dh_priv", "adv_remote_dh_pub"):
        session.pop(key, None)


# Auto-init on startup
_init_session()


# ---------------------------------------------------------------------------
# Routes — Static
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


# ---------------------------------------------------------------------------
# Routes — API
# ---------------------------------------------------------------------------

@app.route("/api/init", methods=["GET"])
def api_init():
    """Reset the session and return the hybrid key-setup metadata."""
    _init_session()
    return jsonify({
        "ok": True,
        "setup": session["ratchet"].setup_meta,
        "alice_state": session["ratchet"].alice.snapshot(),
        "bob_state": session["ratchet"].bob.snapshot(),
        "pqc_available": OQS_AVAILABLE,
    })


@app.route("/api/send", methods=["POST"])
def api_send():
    """
    Send a message.

    Body JSON: { "sender": "Alice"|"Bob", "plaintext": "..." }
    """
    data = request.get_json(force=True)
    sender = data["sender"]
    plaintext = data["plaintext"]

    ratchet: DoubleRatchet = session["ratchet"]

    # Encrypt
    envelope = ratchet.send(sender, plaintext)

    # Store for potential intercept
    session["pending_envelope"] = envelope
    session["envelopes"].append(envelope)

    # Decrypt on the receiver side
    receiver = "Bob" if sender == "Alice" else "Alice"
    result = ratchet.receive(receiver, envelope)

    return jsonify({
        "ok": True,
        "sender": sender,
        "receiver": receiver,
        "plaintext": plaintext,
        "envelope": envelope,
        "decryption": result,
        "alice_state": ratchet.alice.snapshot(),
        "bob_state": ratchet.bob.snapshot(),
    })


@app.route("/api/send_out_of_order", methods=["POST"])
def api_send_out_of_order():
    """
    Simulate sending two messages but delivering them out of order.
    """
    data = request.get_json(force=True)
    sender = data["sender"]
    receiver = "Bob" if sender == "Alice" else "Alice"

    ratchet: DoubleRatchet = session["ratchet"]

    # 1. Encrypt Message 1
    envelope1 = ratchet.send(sender, f"[{sender}] Msg 1 (Delayed)")
    # 2. Encrypt Message 2
    envelope2 = ratchet.send(sender, f"[{sender}] Msg 2 (Arrives first)")

    session["envelopes"].extend([envelope1, envelope2])

    # 3. Receive Message 2 first
    result2 = ratchet.receive(receiver, envelope2)
    # 4. Receive Message 1 later
    result1 = ratchet.receive(receiver, envelope1)

    return jsonify({
        "ok": True,
        "sender": sender,
        "receiver": receiver,
        "envelope1": envelope1,
        "envelope2": envelope2,
        "decryption2": result2,
        "decryption1": result1,
        "alice_state": ratchet.alice.snapshot(),
        "bob_state": ratchet.bob.snapshot(),
    })


@app.route("/api/compromise", methods=["POST"])
def api_compromise():
    """
    Compromise a party's device.

    Body JSON: { "target": "Bob" }
    """
    data = request.get_json(force=True)
    target = data.get("target", "Bob")

    ratchet: DoubleRatchet = session["ratchet"]
    snapshot = ratchet.compromise(target)

    session["compromised_state"] = snapshot

    return jsonify({
        "ok": True,
        "target": target,
        "compromised_state": snapshot,
    })


@app.route("/api/intercept", methods=["POST"])
def api_intercept():
    """
    Attempt to decrypt the last envelope using the compromised state.
    """
    if not session["compromised_state"]:
        return jsonify({"ok": False, "error": "No compromised state available. Compromise a device first."}), 400

    data = request.get_json(force=True) if request.data else {}
    idx = data.get("envelope_index", -1)

    if not session["envelopes"]:
        return jsonify({"ok": False, "error": "No messages to intercept."}), 400

    try:
        envelope = session["envelopes"][idx]
    except IndexError:
        return jsonify({"ok": False, "error": "Invalid envelope index."}), 400

    ratchet: DoubleRatchet = session["ratchet"]

    # Initialize adversary shadow chain state on first intercept
    if "adv_recv_ck" not in session:
        cs = session["compromised_state"]
        session["adv_recv_ck"] = cs.get("recv_chain_key")
        session["adv_send_ck"] = cs.get("send_chain_key")
        session["adv_root_key"] = cs["root_key"]
        session["adv_dh_priv"] = cs["dh_priv"]
        session["adv_remote_dh_pub"] = cs.get("remote_dh_pub")

    result = _adversary_try_decrypt(envelope)

    return jsonify({
        "ok": True,
        "result": result,
        "envelope": envelope,
    })


def _adversary_try_decrypt(envelope: dict) -> dict:
    """Adversary attempts decryption, simulating the full receive path."""
    try:
        sender_dh_pub_hex = envelope["header"]["dh_pub"]
        sender = envelope["sender"]

        if sender == "Alice":
            ck_hex = session.get("adv_recv_ck")
            rk_hex = session["adv_root_key"]
            dh_priv_hex = session["adv_dh_priv"]

            stored_remote = session.get("adv_remote_dh_pub")
            if stored_remote and sender_dh_pub_hex != stored_remote:
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
                dh_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(dh_priv_hex))
                sender_dh_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(sender_dh_pub_hex))
                dh_out = dh_priv.exchange(sender_dh_pub)
                rk = bytes.fromhex(rk_hex)
                new_rk, new_recv_ck = kdf_rk(rk, dh_out)
                session["adv_root_key"] = new_rk.hex()
                session["adv_recv_ck"] = new_recv_ck.hex()
                session["adv_remote_dh_pub"] = sender_dh_pub_hex
                ck_hex = new_recv_ck.hex()

            if not ck_hex:
                return {"success": False, "error": "No receive chain key available in compromised state"}

            ck = bytes.fromhex(ck_hex)
            new_ck, msg_key = kdf_ck(ck)
            session["adv_recv_ck"] = new_ck.hex()

        else:
            ck_hex = session.get("adv_send_ck")
            if not ck_hex:
                return {"success": False, "error": "No send chain key available in compromised state"}
            ck = bytes.fromhex(ck_hex)
            new_ck, msg_key = kdf_ck(ck)
            session["adv_send_ck"] = new_ck.hex()

        nonce = bytes.fromhex(envelope["nonce_hex"])
        ct = bytes.fromhex(envelope["ciphertext_hex"])
        ad = bytes.fromhex(envelope["ad_hex"])

        plaintext = aead_decrypt(msg_key, nonce, ct, ad).decode()

        ratchet: DoubleRatchet = session["ratchet"]
        ratchet.log.append({
            "event": "adversary_decrypt",
            "success": True,
            "plaintext": plaintext,
        })

        return {"success": True, "plaintext": plaintext}

    except Exception as e:
        ratchet: DoubleRatchet = session["ratchet"]
        ratchet.log.append({
            "event": "adversary_decrypt",
            "success": False,
            "error": str(e),
        })
        return {
            "success": False,
            "error": f"Decryption FAILED — {type(e).__name__}: {e}",
        }


# ---------------------------------------------------------------------------
# Benchmarking endpoint
# ---------------------------------------------------------------------------

@app.route("/api/benchmark", methods=["POST"])
def api_benchmark():
    """
    Run N handshakes and return comparative timing data.

    Body JSON: { "iterations": 10 }
    """
    data = request.get_json(force=True) if request.data else {}
    n = min(data.get("iterations", 10), 100)
    results = run_benchmark(n)
    return jsonify({"ok": True, **results})


# ---------------------------------------------------------------------------
# MITM Tamper endpoint
# ---------------------------------------------------------------------------

@app.route("/api/mitm_tamper", methods=["POST"])
def api_mitm_tamper():
    """
    Intercept the last envelope, flip a bit in the ciphertext,
    and attempt decryption to demonstrate AES-256-GCM integrity.

    Body JSON: { "envelope_index": -1, "bit_position": 0 }
    """
    if not session["envelopes"]:
        return jsonify({"ok": False, "error": "No messages to tamper with."}), 400

    data = request.get_json(force=True) if request.data else {}
    idx = data.get("envelope_index", -1)
    bit_pos = data.get("bit_position", 0)

    try:
        envelope = session["envelopes"][idx]
    except IndexError:
        return jsonify({"ok": False, "error": "Invalid envelope index."}), 400

    # Flip a bit in the ciphertext
    ct_bytes = bytes.fromhex(envelope["ciphertext_hex"])
    byte_pos = bit_pos // 8
    bit_offset = bit_pos % 8

    if byte_pos >= len(ct_bytes):
        byte_pos = 0

    tampered = bytearray(ct_bytes)
    tampered[byte_pos] ^= (1 << bit_offset)
    tampered_hex = bytes(tampered).hex()

    # Try to decrypt the tampered ciphertext using the original message key
    nonce = bytes.fromhex(envelope["nonce_hex"])
    ad = bytes.fromhex(envelope["ad_hex"])
    msg_key = bytes.fromhex(envelope["msg_key_hex"])

    try:
        aead_decrypt(msg_key, nonce, bytes(tampered), ad)
        result = {
            "tamper_detected": False,
            "error": "Tamper NOT detected — this should not happen!",
        }
    except Exception as e:
        result = {
            "tamper_detected": True,
            "error_type": type(e).__name__,
            "error_message": str(e),
            "description": "AES-256-GCM authentication tag verification failed. "
                           "The integrity of the ciphertext has been compromised — "
                           "the receiver correctly rejects this tampered packet.",
        }

    ratchet: DoubleRatchet = session["ratchet"]
    ratchet.log.append({
        "event": "mitm_tamper",
        "tamper_detected": result["tamper_detected"],
        "bit_position": bit_pos,
        "byte_position": byte_pos,
    })

    return jsonify({
        "ok": True,
        "original_ct_hex": envelope["ciphertext_hex"][:64] + "…",
        "tampered_ct_hex": tampered_hex[:64] + "…",
        "bit_flipped": bit_pos,
        "byte_flipped": byte_pos,
        "original_byte": f"0x{ct_bytes[byte_pos]:02x}",
        "tampered_byte": f"0x{tampered[byte_pos]:02x}",
        "result": result,
    })


@app.route("/api/state", methods=["GET"])
def api_state():
    """Return current ratchet state for both parties."""
    ratchet: DoubleRatchet = session["ratchet"]
    return jsonify({
        "alice": ratchet.alice.snapshot(),
        "bob": ratchet.bob.snapshot(),
    })


@app.route("/api/log", methods=["GET"])
def api_log():
    """Return the full event log."""
    ratchet: DoubleRatchet = session["ratchet"]
    return jsonify({"log": ratchet.log})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    pqc_status = "✅ REAL (liboqs)" if OQS_AVAILABLE else "⚠️  SIMULATED"
    print(f"\n  🔐  Double Ratchet PQC Benchmarking Suite — http://localhost:{port}")
    print(f"  📦  PQC Status: {pqc_status}\n")
    app.run(debug=True, port=port, host="0.0.0.0")
