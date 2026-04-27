"""Verify the correct demo flow for the UI."""
import urllib.request, json

BASE = "http://localhost:5001/api"

def get(path):
    r = urllib.request.urlopen(f"{BASE}{path}")
    return json.loads(r.read())

def post(path, data):
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    r = urllib.request.urlopen(req)
    return json.loads(r.read())

# Reset
get("/init")
print("=== Session initialized ===\n")

# Step 1: Normal conversation
r = post("/send", {"sender": "Alice", "plaintext": "Hello Bob!"})
print("1. Alice->Bob: OK, ratcheted:", r["decryption"]["ratcheted"])

r = post("/send", {"sender": "Bob", "plaintext": "Hi Alice!"})
print("2. Bob->Alice: OK, ratcheted:", r["decryption"]["ratcheted"])

# Step 2: Compromise Bob
print("\n=== COMPROMISE BOB ===")
comp = post("/compromise", {"target": "Bob"})
print("3. Bob compromised")

# Step 3: Alice sends post-compromise message
r = post("/send", {"sender": "Alice", "plaintext": "Secret post-compromise!"})
print("4. Alice->Bob post-compromise: OK")

# Step 4: Adversary intercepts → should SUCCEED
i = post("/intercept", {})
print("5. INTERCEPT:", "SUCCESS ✓" if i["result"]["success"] else "FAIL ✗",
      "—", i["result"].get("plaintext", i["result"].get("error", ""))[:40])

# Step 5: Bob sends healing message (triggers DH ratchet)
r = post("/send", {"sender": "Bob", "plaintext": "This triggers healing!"})
print("\n=== BOB SENDS HEALING MSG ===")
print("6. Bob->Alice: OK, ratcheted:", r["decryption"]["ratcheted"])

# Step 6: Alice replies (Bob ratchets on receive)
r = post("/send", {"sender": "Alice", "plaintext": "Post-healing from Alice!"})
print("7. Alice->Bob post-healing: OK, ratcheted:", r["decryption"]["ratcheted"])

# Step 7: Adversary intercepts → should FAIL
i = post("/intercept", {})
print("8. INTERCEPT:", "SUCCESS ✗ (BAD)" if i["result"]["success"] else "FAIL ✓ (Future Secrecy!)",
      "—", i["result"].get("error", i["result"].get("plaintext", ""))[:60])
