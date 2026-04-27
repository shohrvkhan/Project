# Double Ratchet PQC Benchmarking Suite

> **Portfolio Project:** Applied Cryptographic Protocols for Trap-Resilient Communication Channels
> **Author:** Shohruhbek Axmadjonov

A professional cryptographic protocol simulator and benchmarking suite demonstrating the mechanics of the Double Ratchet Protocol, Post-Quantum Cryptography (PQC), and Active Adversary simulations.

---

## 🎯 Project Motivation

With the advent of quantum computing, classical asymmetric cryptography (like RSA and ECC) faces an existential threat from Shor's algorithm. This project was developed to explore and visualize **Post-Quantum Security** in modern communication protocols. By integrating **CRYSTALS-Kyber-768 (ML-KEM-768)** alongside classical ECC algorithms, this application provides a "Dual-Track" hybrid architecture, ensuring that quantum resilience is achieved without sacrificing classical security guarantees.

---

## 🛠 Tech Stack

- **Backend Framework:** Flask (Python)
- **Classical Cryptography:** `cryptography` (X25519, HKDF-SHA256, AES-256-GCM)
- **Post-Quantum Cryptography:** CRYSTALS-Kyber-768 via `liboqs` and `oqs-python`
- **Frontend / Visualization:** Vanilla JavaScript, Tailwind CSS, Chart.js, Lucide Icons

---

## ✨ Key Features

1. **Double Ratchet Protocol Simulation**
   - Implements a fully functional Double Ratchet state machine with a symmetric-key KDF chain and an asymmetric DH ratchet.
   - Demonstrates **Future Secrecy (Healing)** by proving that compromised states become useless after a DH ratchet step.
2. **Out-of-Order Message Handling**
   - Robust skipped message key derivation capable of storing up to 100 missed keys to prevent DoS attacks.
   - Includes a "Network Jitter" simulation to visualize asynchronous key recovery mechanics.
3. **Active Adversary (MITM) Simulator**
   - Allows users to simulate a state-compromise attack and intercept network traffic.
   - **Tamper Packet functionality:** Demonstrates AES-256-GCM integrity validation by flipping ciphertext bits and visually rendering the resulting `InvalidTag` Integrity Errors.

---

## 📊 Benchmarking & Performance

The suite includes a real-time benchmarking dashboard powered by Chart.js to quantify the overhead introduced by Post-Quantum Cryptography.

### How to Interpret the Results
- **Latency (ms):** Compares the execution time of a classical X25519 handshake against a Hybrid (X25519 + Kyber768) handshake.
- **Bandwidth Overhead (Bytes):** Visualizes the payload size differences. Kyber768 introduces significant key-size overhead compared to lightweight ECC.
- **CPU Time:** Breaks down the specific encapsulation and decapsulation timings for the PQC algorithms, helping assess feasibility on constrained devices.

---

## 🚀 Quick Start

### 1. Install Dependencies
Ensure you have Python 3.9+ installed.
```bash
pip install -r requirements.txt
```
*(Note: To use the real PQC features, the native `liboqs` library must be built and linked. Otherwise, a size-accurate simulation is used.)*

### 2. Run the Application
```bash
python3 app.py
```
Navigate to **http://localhost:5001** in your browser.

---

## 📝 License
MIT License. See `LICENSE` for details.
