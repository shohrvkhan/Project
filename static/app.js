/**
 * Frontend logic for the Double Ratchet Trap-Resilient Communication Demo.
 *
 * Communicates with the Flask backend via REST API and updates the three-panel
 * dashboard: Alice, Bob, and the Adversary.
 */

// ─── API helpers ─────────────────────────────────────────────────────────────

const API = {
  async init() {
    const r = await fetch("/api/init");
    return r.json();
  },
  async send(sender, plaintext) {
    const r = await fetch("/api/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender, plaintext }),
    });
    return r.json();
  },
  async compromise(target) {
    const r = await fetch("/api/compromise", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    return r.json();
  },
  async intercept() {
    const r = await fetch("/api/intercept", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    return r.json();
  },
};


// ─── Color constants ─────────────────────────────────────────────────────────

const COLORS = {
  alice:      '#6366f1',
  aliceLight: '#818cf8',
  aliceDark:  '#4f46e5',
  bob:        '#06b6d4',
  bobLight:   '#22d3ee',
  bobDark:    '#0891b2',
  threat:     '#ef4444',
  threatLight:'#f87171',
  success:    '#22c55e',
  surface800: '#0f172a',
};


// ─── State ───────────────────────────────────────────────────────────────────

let isCompromised = false;
let messageCount = 0;
let messagesSinceCompromise = 0;
let bobSentSinceCompromise = false;
let aliceSentAfterBobHealing = false;
let isHealed = false;
let isSending = false;


// ─── DOM refs ────────────────────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const aliceMessages   = $("#alice-messages");
const bobMessages     = $("#bob-messages");
const aliceInput      = $("#alice-input");
const bobInput        = $("#bob-input");
const trafficLog      = $("#traffic-log");
const stolenKeys      = $("#stolen-keys");
const interceptResults = $("#intercept-results");
const setupBanner     = $("#setup-banner");
const setupDetails    = $("#setup-details");


// ─── Lucide icon helper ──────────────────────────────────────────────────────

function refreshIcons() {
  if (window.lucide) {
    lucide.createIcons();
  }
}


// ─── Initialization ──────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initSession();
});


async function initSession() {
  const data = await API.init();

  // Reset UI state
  isCompromised = false;
  isHealed = false;
  isSending = false;
  messageCount = 0;
  messagesSinceCompromise = 0;
  bobSentSinceCompromise = false;
  aliceSentAfterBobHealing = false;
  aliceMessages.innerHTML = "";
  bobMessages.innerHTML = "";
  trafficLog.innerHTML = '<p class="text-slate-600 italic">No messages intercepted yet…</p>';
  stolenKeys.innerHTML = "";
  interceptResults.innerHTML = "";
  $("#compromised-state").classList.add("hidden");
  $("#btn-intercept").disabled = true;

  // Reset compromise button
  const compBtn = $("#btn-compromise");
  compBtn.disabled = false;
  compBtn.style.opacity = "";

  // Reset Bob panel state
  const bobPanel = $("#panel-bob");
  bobPanel.classList.remove("bob-compromised", "bob-healed");
  bobPanel.style.borderColor = "";

  const bobDot = $("#bob-status-dot");
  const bobText = $("#bob-status-text");
  if (bobDot) {
    bobDot.style.background = COLORS.bob;
  }
  if (bobText) {
    bobText.textContent = "Online";
    bobText.style.color = COLORS.bobLight;
  }

  // Reset stolen keys container
  const stolenContainer = $("#stolen-keys-container");
  if (stolenContainer) {
    stolenContainer.classList.remove("stolen-keys-active", "stolen-keys-stale");
  }

  // Show setup banner
  if (data.setup) {
    setupBanner.classList.remove("hidden");
    setupDetails.innerHTML = `
      <div class="rounded-lg p-2.5 setup-key-card" data-key="ecc" style="background: rgba(15,23,42,0.5); border: 1px solid rgba(51,65,85,0.3);">
        <div class="flex items-center gap-1.5 mb-1">
          <i data-lucide="key-round" class="w-3 h-3" style="color: ${COLORS.aliceLight};"></i>
          <span class="text-[10px] font-semibold" style="color: ${COLORS.aliceLight};">ECC (X25519)</span>
        </div>
        <span class="text-slate-400 break-all text-xs">${data.setup.ecc_shared_hex}</span>
      </div>
      <div class="rounded-lg p-2.5 setup-key-card" data-key="pqc" style="background: rgba(15,23,42,0.5); border: 1px solid rgba(51,65,85,0.3);">
        <div class="flex items-center gap-1.5 mb-1">
          <i data-lucide="shield" class="w-3 h-3" style="color: ${COLORS.bobLight};"></i>
          <span class="text-[10px] font-semibold" style="color: ${COLORS.bobLight};">PQC (Kyber)</span>
        </div>
        <span class="text-slate-400 break-all text-xs">${data.setup.pqc_shared_hex}</span>
      </div>
      <div class="rounded-lg p-2.5 setup-key-card" data-key="root" style="background: rgba(15,23,42,0.5); border: 1px solid rgba(51,65,85,0.3);">
        <div class="flex items-center gap-1.5 mb-1">
          <i data-lucide="lock" class="w-3 h-3" style="color: #34d399;"></i>
          <span class="text-[10px] font-semibold" style="color: #34d399;">Combined Root Key</span>
        </div>
        <span class="text-slate-400 break-all text-xs">${data.setup.root_key_hex.slice(0, 24)}…</span>
      </div>
      <div class="rounded-lg p-2.5 setup-key-card" data-key="kem" style="background: rgba(15,23,42,0.5); border: 1px solid rgba(51,65,85,0.3);">
        <div class="flex items-center gap-1.5 mb-1">
          <i data-lucide="cpu" class="w-3 h-3" style="color: #fbbf24;"></i>
          <span class="text-[10px] font-semibold" style="color: #fbbf24;">KEM Algorithm</span>
        </div>
        <span class="text-slate-400 text-xs">${data.setup.pqc_kem}</span>
      </div>
    `;
  }

  // Update ratchet info
  updateRatchetInfo(data.alice_state, data.bob_state);

  // Add system message
  addSystemMessage(aliceMessages, "🔐 Session initialized. Hybrid PQC+ECC key setup complete.");
  addSystemMessage(bobMessages, "🔐 Session initialized. Hybrid PQC+ECC key setup complete.");

  refreshIcons();
}


async function resetSession() {
  const resetBtn = $("#btn-reset");
  resetBtn.textContent = "Resetting…";
  resetBtn.disabled = true;
  await initSession();
  resetBtn.innerHTML = '<i data-lucide="rotate-ccw" class="w-4 h-4"></i> Reset';
  resetBtn.disabled = false;
  refreshIcons();
}


// ─── Send Message ────────────────────────────────────────────────────────────

async function sendMessage(event, sender) {
  event.preventDefault();

  if (isSending) return;

  const input = sender === "Alice" ? aliceInput : bobInput;
  const plaintext = input.value.trim();
  if (!plaintext) return;

  input.value = "";
  isSending = true;

  const senderPanel   = sender === "Alice" ? aliceMessages : bobMessages;
  const receiverPanel = sender === "Alice" ? bobMessages   : aliceMessages;
  const receiver      = sender === "Alice" ? "Bob" : "Alice";

  messageCount++;

  // 1. Show sent message in sender panel
  addSentMessage(senderPanel, plaintext, sender);

  // 2. Call API
  const data = await API.send(sender, plaintext);

  // 3. Show ciphertext in network traffic
  addTrafficEntry(data.envelope, sender, receiver);

  // 4. Show "receiving" animation then decrypted message
  await showReceivingAnimation(receiverPanel, data, receiver);

  // 5. Update ratchet info
  updateRatchetInfo(data.alice_state, data.bob_state);

  // 6. Pulse setup banner keys if DH ratchet occurred
  if (data.decryption && data.decryption.ratcheted) {
    pulseSetupKeys();
  }

  // 7. Track post-compromise state for healing detection
  if (isCompromised && !isHealed) {
    messagesSinceCompromise++;

    if (sender === "Bob" && !bobSentSinceCompromise) {
      bobSentSinceCompromise = true;
      addSystemMessage(bobMessages, "🔄 DH ratchet triggered — fresh entropy mixed into key chain.");
    }

    if (sender === "Alice" && bobSentSinceCompromise && !aliceSentAfterBobHealing) {
      aliceSentAfterBobHealing = true;
      isHealed = true;

      const bobPanel = $("#panel-bob");
      bobPanel.classList.remove("bob-compromised");
      bobPanel.classList.add("heal-pulse");
      setTimeout(() => {
        bobPanel.classList.remove("heal-pulse");
        bobPanel.classList.add("bob-healed");
      }, 1200);

      const stolenContainer = $("#stolen-keys-container");
      if (stolenContainer) {
        stolenContainer.classList.remove("stolen-keys-active");
        stolenContainer.classList.add("stolen-keys-stale");
      }

      const bobDot = $("#bob-status-dot");
      const bobText = $("#bob-status-text");
      if (bobDot) bobDot.style.background = COLORS.success;
      if (bobText) {
        bobText.textContent = "Healed";
        bobText.style.color = "#34d399";
      }

      addSystemMessage(bobMessages, "🛡️ Full DH round-trip complete — future secrecy restored. Adversary's stolen keys are now useless.");
    }
  }

  isSending = false;
}


// ─── Compromise ──────────────────────────────────────────────────────────────

async function compromiseBob() {
  const data = await API.compromise("Bob");

  isCompromised = true;
  isHealed = false;
  messagesSinceCompromise = 0;
  bobSentSinceCompromise = false;
  aliceSentAfterBobHealing = false;

  // Flash effect on adversary panel
  const advPanel = $("#panel-adversary");
  advPanel.classList.add("compromise-flash");
  setTimeout(() => advPanel.classList.remove("compromise-flash"), 800);

  // Mark Bob's panel as compromised
  const bobPanel = $("#panel-bob");
  bobPanel.classList.add("bob-compromised");

  // Update Bob's status indicator
  const bobDot = $("#bob-status-dot");
  const bobText = $("#bob-status-text");
  if (bobDot) bobDot.style.background = COLORS.threat;
  if (bobText) {
    bobText.textContent = "Compromised";
    bobText.style.color = COLORS.threatLight;
  }

  // Show stolen keys with active glow
  const state = data.compromised_state;
  $("#compromised-state").classList.remove("hidden");
  const stolenContainer = $("#stolen-keys-container");
  if (stolenContainer) {
    stolenContainer.classList.add("stolen-keys-active");
    stolenContainer.classList.remove("stolen-keys-stale");
  }

  stolenKeys.innerHTML = `
    <div class="key-row">
      <span class="key-label"><i data-lucide="key-round" class="w-3 h-3"></i> Root Key</span>
      <span class="key-value" title="${state.root_key}">${state.root_key.slice(0, 20)}…</span>
    </div>
    <div class="key-row">
      <span class="key-label"><i data-lucide="arrow-up" class="w-3 h-3"></i> Send Chain</span>
      <span class="key-value" title="${state.send_chain_key || 'null'}">${state.send_chain_key ? state.send_chain_key.slice(0, 20) + '…' : 'null'}</span>
    </div>
    <div class="key-row">
      <span class="key-label"><i data-lucide="arrow-down" class="w-3 h-3"></i> Recv Chain</span>
      <span class="key-value" title="${state.recv_chain_key || 'null'}">${state.recv_chain_key ? state.recv_chain_key.slice(0, 20) + '…' : 'null'}</span>
    </div>
    <div class="key-row">
      <span class="key-label"><i data-lucide="lock" class="w-3 h-3"></i> DH Private</span>
      <span class="key-value" title="${state.dh_priv}">${state.dh_priv.slice(0, 20)}…</span>
    </div>
    <div class="key-row">
      <span class="key-label"><i data-lucide="unlock" class="w-3 h-3"></i> DH Public</span>
      <span class="key-value" title="${state.dh_pub}">${state.dh_pub.slice(0, 20)}…</span>
    </div>
  `;

  // Enable intercept
  $("#btn-intercept").disabled = false;

  // Disable compromise button
  const compBtn = $("#btn-compromise");
  compBtn.disabled = true;
  compBtn.style.opacity = "0.5";

  // System messages
  addSystemMessage(bobMessages, "⚠️ DEVICE COMPROMISED — all cryptographic state stolen by adversary.");
  addAdversaryResult(interceptResults, "success",
    "✅ Bob's device fully compromised. All keys, chain state, and DH private key extracted.",
    `Ratchet step at compromise: ${state.ratchet_step}`
  );

  refreshIcons();
}


// ─── Intercept ───────────────────────────────────────────────────────────────

async function interceptMessage() {
  const data = await API.intercept();

  if (!data.ok) {
    addAdversaryResult(interceptResults, "fail", `❌ ${data.error}`);
    return;
  }

  const result = data.result;

  if (result.success) {
    addAdversaryResult(interceptResults, "success",
      `✅ Decryption SUCCESS — message compromised!`,
      `Plaintext: "${result.plaintext}"`,
    );

    const advPanel = $("#panel-adversary");
    advPanel.classList.add("success-glow");
    setTimeout(() => advPanel.classList.remove("success-glow"), 1000);
  } else {
    addAdversaryResult(interceptResults, "fail",
      `🔒 Decryption FAILED — Future Secrecy Proven!`,
      result.error
    );

    const btn = $("#btn-intercept");
    btn.classList.add("shake");
    setTimeout(() => btn.classList.remove("shake"), 500);

    addSystemMessage(bobMessages, "✅ Adversary decryption attempt FAILED — trap-resilience confirmed.");
  }
}


// ─── Setup banner key pulse ──────────────────────────────────────────────────

function pulseSetupKeys() {
  const cards = document.querySelectorAll(".setup-key-card");
  cards.forEach((card, i) => {
    setTimeout(() => {
      card.classList.add("key-pulse");
      setTimeout(() => card.classList.remove("key-pulse"), 800);
    }, i * 150);
  });
}


// ─── UI Builders ─────────────────────────────────────────────────────────────

function addSentMessage(panel, text, sender) {
  const isAlice = sender === "Alice";
  const gradient = isAlice
    ? `linear-gradient(to right, ${COLORS.alice}, ${COLORS.aliceDark})`
    : `linear-gradient(to right, ${COLORS.bob}, ${COLORS.bobDark})`;
  const shadowColor = isAlice ? COLORS.alice : COLORS.bob;
  const avatarBg = isAlice
    ? `linear-gradient(to bottom right, rgba(99,102,241,0.25), rgba(99,102,241,0.12))`
    : `linear-gradient(to bottom right, rgba(6,182,212,0.25), rgba(6,182,212,0.12))`;
  const iconColor = isAlice ? COLORS.aliceLight : COLORS.bobLight;

  const wrapper = document.createElement("div");
  wrapper.className = `msg-bubble flex ${isAlice ? "justify-end" : "justify-start"}`;
  wrapper.innerHTML = `
    <div class="max-w-[85%] flex items-end gap-2 ${isAlice ? 'flex-row-reverse' : ''}">
      <div class="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style="background: ${avatarBg};">
        <i data-lucide="user" class="w-3.5 h-3.5" style="color: ${iconColor};"></i>
      </div>
      <div class="rounded-2xl px-4 py-2.5 shadow-lg" style="background: ${gradient}; box-shadow: 0 4px 15px -3px ${shadowColor}40;">
        <p class="text-sm text-white leading-relaxed">${escapeHtml(text)}</p>
        <span class="text-[10px] mt-1 block" style="color: rgba(255,255,255,0.5);">${timestamp()} · Sent</span>
      </div>
    </div>
  `;
  panel.appendChild(wrapper);
  scrollToBottom(panel);
  refreshIcons();
}


function addReceivedMessage(panel, text, sender, envelope, ratcheted) {
  const isFromAlice = sender === "Alice";
  const borderColor = isFromAlice ? "rgba(99,102,241,0.2)" : "rgba(6,182,212,0.2)";
  const labelColor  = isFromAlice ? COLORS.aliceLight : COLORS.bobLight;
  const avatarBg = isFromAlice
    ? `linear-gradient(to bottom right, rgba(99,102,241,0.25), rgba(99,102,241,0.12))`
    : `linear-gradient(to bottom right, rgba(6,182,212,0.25), rgba(6,182,212,0.12))`;

  const wrapper = document.createElement("div");
  wrapper.className = `msg-bubble flex ${isFromAlice ? "justify-start" : "justify-end"}`;

  let ratchetBadge = "";
  if (ratcheted) {
    ratchetBadge = `<span class="ratchet-badge inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full font-medium mt-1" style="color: #34d399; background: rgba(52,211,153,0.1);">
      <i data-lucide="refresh-cw" class="w-3 h-3"></i>
      DH Ratchet Step
    </span>`;
  }

  wrapper.innerHTML = `
    <div class="max-w-[85%] flex items-end gap-2 ${isFromAlice ? '' : 'flex-row-reverse'}">
      <div class="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style="background: ${avatarBg};">
        <i data-lucide="user" class="w-3.5 h-3.5" style="color: ${labelColor};"></i>
      </div>
      <div class="space-y-1.5">
        <div class="rounded-xl px-3 py-1.5" style="background: rgba(15,23,42,0.6); border: 1px solid ${borderColor};">
          <span class="text-[10px] font-semibold" style="color: ${labelColor};">Ciphertext:</span>
          <p class="text-[11px] font-mono text-slate-500 break-all cipher-reveal">${envelope.ciphertext_hex.slice(0, 48)}…</p>
        </div>
        <div class="rounded-2xl px-4 py-2.5 shadow-sm" style="background: #0f172a; border: 1px solid ${borderColor};">
          <p class="text-sm text-white leading-relaxed">${escapeHtml(text)}</p>
          <div class="flex items-center gap-2 mt-1 flex-wrap">
            <span class="text-[10px] text-slate-500">${timestamp()} · from ${sender}</span>
            ${ratchetBadge}
          </div>
        </div>
      </div>
    </div>
  `;
  panel.appendChild(wrapper);
  scrollToBottom(panel);
  refreshIcons();
}


function addSystemMessage(panel, text) {
  const wrapper = document.createElement("div");
  wrapper.className = "msg-bubble flex justify-center";

  let iconName = "info";
  if (text.includes("🔐") || text.includes("Session")) iconName = "shield-check";
  else if (text.includes("⚠️") || text.includes("COMPROMISED")) iconName = "alert-triangle";
  else if (text.includes("🔄") || text.includes("ratchet")) iconName = "refresh-cw";
  else if (text.includes("🛡️") || text.includes("restored")) iconName = "shield";
  else if (text.includes("✅")) iconName = "check-circle";

  wrapper.innerHTML = `
    <div class="inline-flex items-center gap-2 px-4 py-2 rounded-full backdrop-blur-sm" style="background: rgba(15,23,42,0.8); border: 1px solid rgba(51,65,85,0.3);">
      <i data-lucide="${iconName}" class="w-3.5 h-3.5 text-slate-400 flex-shrink-0"></i>
      <span class="text-[11px] text-slate-400 font-medium">${text}</span>
    </div>
  `;
  panel.appendChild(wrapper);
  scrollToBottom(panel);
  refreshIcons();
}


function addTrafficEntry(envelope, sender, receiver) {
  if (trafficLog.querySelector("p.italic")) {
    trafficLog.innerHTML = "";
  }

  const arrowColor = sender === "Alice" ? COLORS.aliceLight : COLORS.bobLight;

  const entry = document.createElement("div");
  entry.className = "traffic-entry rounded-lg p-2.5";
  entry.style.cssText = "background: rgba(15,23,42,0.6); border: 1px solid rgba(51,65,85,0.2);";
  entry.innerHTML = `
    <div class="flex items-center justify-between mb-1">
      <div class="flex items-center gap-1.5">
        <i data-lucide="arrow-right" class="w-3 h-3" style="color: ${arrowColor};"></i>
        <span class="text-[10px] font-semibold" style="color: ${arrowColor};">${sender} → ${receiver}</span>
      </div>
      <span class="text-[10px] text-slate-600">#${messageCount}</span>
    </div>
    <div class="text-[10px] text-slate-500 break-all leading-relaxed">${envelope.ciphertext_hex.slice(0, 64)}…</div>
  `;
  trafficLog.prepend(entry);
  refreshIcons();

  while (trafficLog.children.length > 20) {
    trafficLog.removeChild(trafficLog.lastChild);
  }
}


function addAdversaryResult(container, type, title, detail) {
  const iconName = type === "success" ? "check-circle" : "x-circle";
  const card = document.createElement("div");
  card.className = `intercept-card msg-bubble ${type === "success" ? "intercept-success" : "intercept-fail"}`;
  card.innerHTML = `
    <div class="flex items-start gap-2">
      <i data-lucide="${iconName}" class="w-4 h-4 flex-shrink-0 mt-0.5"></i>
      <div>
        <p class="font-semibold text-sm">${title}</p>
        ${detail ? `<p class="text-xs mt-1 opacity-80">${escapeHtml(detail)}</p>` : ""}
      </div>
    </div>
  `;
  container.prepend(card);
  refreshIcons();
}


async function showReceivingAnimation(panel, data, receiver) {
  const typing = document.createElement("div");
  typing.className = "msg-bubble flex justify-start";
  typing.innerHTML = `
    <div class="rounded-2xl px-5 py-3" style="background: rgba(15,23,42,0.6); border: 1px solid rgba(51,65,85,0.2);">
      <div class="typing-dots text-slate-400 flex gap-1">
        <span></span><span></span><span></span>
      </div>
    </div>
  `;
  panel.appendChild(typing);
  scrollToBottom(panel);

  await sleep(600);

  panel.removeChild(typing);

  addReceivedMessage(
    panel,
    data.decryption.plaintext,
    data.sender,
    data.envelope,
    data.decryption.ratcheted
  );
}


function updateRatchetInfo(aliceState, bobState) {
  $("#alice-ratchet-info").textContent = `Ratchet step: ${aliceState.ratchet_step} · Msgs sent: ${aliceState.send_msg_no}`;
  $("#bob-ratchet-info").textContent = `Ratchet step: ${bobState.ratchet_step} · Msgs sent: ${bobState.send_msg_no}`;
}


// ─── Scroll helper ───────────────────────────────────────────────────────────

function scrollToBottom(container) {
  requestAnimationFrame(() => {
    container.scrollTo({
      top: container.scrollHeight,
      behavior: "smooth",
    });
  });
}


// ─── Utilities ───────────────────────────────────────────────────────────────

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function timestamp() {
  return new Date().toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
