# Trap-Resilient Communication — Double Ratchet Protocol Demo

> **University Project**: Applied Cryptographic Protocols for Trap-Resilient Communication Channels

An interactive web application that demonstrates how the **Double Ratchet Protocol** (as used in Signal) establishes encrypted communication, how a state-compromise attack can temporarily break confidentiality, and how the protocol **self-heals** to achieve **Future Secrecy** (Trap-Resilience).

---

## 🔐 What This Demonstrates

| Concept | Description |
|---|---|
| **Double Ratchet** | Combines a symmetric-key KDF chain (HKDF-SHA256) with an asymmetric DH ratchet (X25519) to derive unique message keys |
| **AEAD Encryption** | Every message is encrypted with AES-256-GCM using a unique message key |
| **Hybrid Key Setup** | Simulates a post-quantum hybrid handshake (CRYSTALS-Kyber + X25519) to derive the initial root key |
| **State-Compromise Attack** | An adversary fully compromises Bob's device, stealing all keys and DH private key |
| **Future Secrecy (Healing)** | After a full DH round-trip (Bob sends → Alice replies), the adversary's stolen keys become useless |

---

## 📋 Prerequisites

- **Python 3.9+** (tested on 3.9, 3.10, 3.11, 3.12)
- **pip** (Python package manager)
- A modern web browser (Chrome, Firefox, Safari, Edge)

---

## 🚀 Quick Start

### 1. Clone / Download the Project

```bash
cd /path/to/project
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `flask` — lightweight web framework
- `cryptography` — X25519, HKDF, AES-GCM primitives
- `flask-cors` — Cross-Origin Resource Sharing support

### 3. Run the Application

```bash
python3 app.py
```

You should see:

```
  🔐  Double Ratchet Demo — http://localhost:5001
```

### 4. Open in Browser

Navigate to **http://localhost:5001** in your browser.

---

## 🎮 How to Use the Demo

The interface has three panels:

| Panel | Purpose |
|---|---|
| **Alice** (left) | Type and send messages as Alice |
| **Bob** (center) | Type and send messages as Bob |
| **Adversary** (right) | Compromise devices, intercept & decrypt messages |

### Step-by-Step Walkthrough

#### Phase 1 — Normal Encrypted Chat
1. Type a message in **Alice's** input field and click **Send**
2. Observe: the ciphertext appears in Bob's panel before the decrypted message
3. Type a reply in **Bob's** input field and click **Send**
4. Both parties can now chat normally with end-to-end encryption

#### Phase 2 — State-Compromise Attack
5. Click the red **"COMPROMISE BOB'S DEVICE"** button in the Adversary panel
6. Observe: Bob's **Root Key**, **Chain Keys**, and **DH Private Key** are now visible in the Adversary panel
7. Have **Alice send a new message** (post-compromise)
8. Click **"Intercept & Decrypt Last Message"** in the Adversary panel
9. ✅ **Result: Decryption SUCCESS** — the adversary can read the intercepted message!

#### Phase 3 — Healing (Future Secrecy)
10. Have **Bob send any message** — this triggers a DH ratchet step (new entropy)
11. Have **Alice reply** — this completes the DH round-trip
12. Click **"Intercept & Decrypt Last Message"** again
13. 🔒 **Result: Decryption FAILED — Future Secrecy Proven!**

> The adversary's stolen keys are now **permanently useless**. The DH ratchet introduced new key material that the adversary cannot derive, even with the old private key.

#### Reset
- Click the **"↻ Reset"** button in the header to start a fresh session at any time.

---

## 🏗️ Project Structure

```
.
├── app.py                # Flask backend — REST API endpoints
├── crypto_engine.py      # Cryptographic engine — Double Ratchet, HKDF, AES-GCM, X25519
├── requirements.txt      # Python dependencies
├── README.md             # This file
├── test_flow.py          # Automated API test script
└── static/
    ├── index.html        # Main UI — three-panel dashboard
    ├── style.css         # Custom animations and styling
    └── app.js            # Frontend logic — API calls, message rendering, UI state
```

---

## 🔧 Technical Architecture

### Backend (`crypto_engine.py`)

```
HybridKeySetup
  ├── X25519 DH exchange (real ECC)
  ├── CRYSTALS-Kyber KEM (simulated)
  └── HKDF-SHA256 combination → Root Key

DoubleRatchet
  ├── kdf_rk()   — Root Key KDF:   RK + DH_output → (new_RK, Chain_Key)
  ├── kdf_ck()   — Chain Key KDF:  CK → (new_CK, Message_Key)
  ├── send()     — Advance send chain → AEAD encrypt
  ├── receive()  — DH ratchet check → advance recv chain → AEAD decrypt
  └── compromise() — Snapshot all state for adversary simulation
```

### API Endpoints (`app.py`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Serve the UI |
| `GET` | `/api/init` | Reset session, return hybrid setup metadata |
| `POST` | `/api/send` | Encrypt & send a message (`{"sender": "Alice", "plaintext": "..."}`) |
| `POST` | `/api/compromise` | Compromise a party (`{"target": "Bob"}`) |
| `POST` | `/api/intercept` | Adversary attempts decryption with stale state |
| `GET` | `/api/state` | Return current ratchet state for both parties |
| `GET` | `/api/log` | Return full event timeline |

### Frontend (`static/`)

- **Tailwind CSS** (CDN) + custom CSS animations
- **Vanilla JavaScript** — no framework dependencies
- Real-time ciphertext display, DH ratchet step badges, typing animations
- Visual feedback: compromise flash, heal pulse, shake on decryption failure

---

## 🧪 Automated Testing

Run the automated API test to verify the healing mechanism:

```bash
python3 test_flow.py
```

Expected output:

```
=== Session initialized ===

1. Alice->Bob: OK, ratcheted: False
2. Bob->Alice: OK, ratcheted: True

=== COMPROMISE BOB ===
3. Bob compromised
4. Alice->Bob post-compromise: OK
5. INTERCEPT: SUCCESS ✓ — Secret post-compromise!

=== BOB SENDS HEALING MSG ===
6. Bob->Alice: OK, ratcheted: True
7. Alice->Bob post-healing: OK, ratcheted: True
8. INTERCEPT: FAIL ✓ (Future Secrecy!) — Decryption FAILED — InvalidTag:
```

---

## 📚 Cryptographic Primitives Used

| Primitive | Standard | Purpose |
|---|---|---|
| **X25519** | RFC 7748 | Elliptic-curve Diffie-Hellman key exchange |
| **HKDF-SHA256** | RFC 5869 | Key derivation for root key and chain key ratchets |
| **AES-256-GCM** | NIST SP 800-38D | Authenticated encryption with associated data |
| **CRYSTALS-Kyber** | NIST FIPS 203 (simulated) | Post-quantum KEM for hybrid key setup |

---

## ⚠️ Disclaimer

This application is a **demonstration/educational tool** for a university project. It is **not** intended for production use. The PQC component is simulated (random bytes stand in for Kyber KEM output). The session state is stored in-memory and is not persistent.

---

## 📝 License

This project was developed as part of the university module *Applied Cryptographic Protocols for Trap-Resilient Communication Channels*. It may be used for educational purposes.
