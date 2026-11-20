"use strict";
// Local test battery for SAFARI-1. Spawns the real server with a dummy HMAC
// secret and a throwaway seen-set file, then sends signed synthetic
// envelopes covering: preflight, a valid task, every trap class in spec §6,
// bad-signature/malformed handling, proof_tx reuse (incl. across a server
// restart), and proof verification + timing.
//
// Run: npm test
const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const snarkjs = require("snarkjs");

const SECRET = "test-secret-local";
const PORT = 18777;
const BASE = `http://127.0.0.1:${PORT}`;
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xDe42aBcDeF0123456789aBcDeF0123456789f001";
const ADDR2 = "0x0000000000000000000000000000000000000999";
const vkJson = require("../circuits/verification_key.json");

const seenPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "gk-test-")), "seen.txt");

let failures = 0;
function check(label, cond, extra = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}${extra ? " — " + extra : ""}`);
  if (!cond) failures++;
}

function sign(body) {
  return crypto.createHmac("sha256", SECRET).update(body).digest("hex");
}

async function post(obj, { badSignature = false, unsigned = false, rawBody = null } = {}) {
  const body = rawBody !== null ? rawBody : JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (!unsigned) headers["x-agent-games-signature"] = badSignature ? "0".repeat(64) : sign(body);
  const t0 = Date.now();
  const res = await fetch(`${BASE}/agent`, { method: "POST", headers, body });
  const text = await res.text();
  const ms = Date.now() - t0;
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  // Verify the response's own signature the way the platform would.
  const presented = res.headers.get("x-agent-games-signature");
  const sigOk = presented === sign(text);
  return { status: res.status, json, sigOk, ms };
}

let txCounter = 0;
function validInput(overrides = {}) {
  txCounter += 1;
  return {
    registered_vk: VK_HASH,
    proof_vk: VK_HASH,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0x" + txCounter.toString(16).padStart(64, "0"),
    ...overrides,
  };
}
function taskEnvelope(input) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_test_" + Math.random().toString(36).slice(2, 8),
    mode: "practice",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
  };
}

function startServer() {
  const child = spawn("node", [path.join(__dirname, "..", "src", "server.js")], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      SEEN_TX_PATH: seenPath,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stderr.on("data", (d) => process.stderr.write("[server] " + d));
  return child;
}

async function waitForHealth() {
  for (let i = 0; i < 50; i++) {
    try {
      const res = await fetch(`${BASE}/health`);
      if (res.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function expectTrap(label, inputOverrides, expectedReason) {
  const r = await post(taskEnvelope(validInput(inputOverrides)));
  check(
    `${label} -> REJECT/${expectedReason}`,
    r.status === 200 && r.json.decision === "REJECT" && r.json.reason_code === expectedReason,
    `got ${r.status} ${r.json && r.json.decision}/${r.json && r.json.reason_code}`
  );
  check(`${label}: response signed`, r.sigOk);
  const hasProof = r.json.proof && r.json.proof.pi_a && Array.isArray(r.json.public_signals) && r.json.public_signals.length === 13;
  check(`${label}: decision=0 proof attached + verifies`, hasProof && (await snarkjs.groth16.verify(vkJson, r.json.public_signals, r.json.proof)));
  return r;
}

(async () => {
  let child = startServer();
  try {
    check("server starts and /health answers", await waitForHealth());

    // --- Preflight ---
    let r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" });
    check("preflight -> 200 {ok:true, protocolVersion:'v1'}", r.status === 200 && r.json.ok === true && r.json.protocolVersion === "v1");
    check("preflight response signed", r.sigOk);
    r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", nonce: "abc123" }, { unsigned: true });
    check("preflight unsigned -> 401", r.status === 401);
    r = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", nonce: "abc123" }, { badSignature: true });
    check("preflight bad signature -> 401", r.status === 401);

    // --- Valid task ---
    const validEnv = taskEnvelope(validInput());
    r = await post(validEnv);
    check("valid task -> APPROVE/VALID_CONDITION", r.status === 200 && r.json.decision === "APPROVE" && r.json.reason_code === "VALID_CONDITION",
      `got ${r.json && r.json.decision}/${r.json && r.json.reason_code}`);
    check("valid task: response signed", r.sigOk);
    check("valid task: proof + 13 public signals", r.json.proof && r.json.proof.pi_a && r.json.public_signals.length === 13);
    check("valid task: proof verifies against exported VK", await snarkjs.groth16.verify(vkJson, r.json.public_signals, r.json.proof));
    check("valid task: proof_tx echoed", r.json.proof_tx === validEnv.input.proof_tx);
    console.log(`INFO  valid task end-to-end latency: ${r.ms} ms`);

    // Direct proof-generation timing (the number that matters vs the 60 s deadline).
    const proofModule = require("../src/proof");
    const { normalizeInput } = require("../src/decision");
    const { buildWitnessInput } = require("../src/witness");
    const norm = normalizeInput(validInput());
    const witness = buildWitnessInput({ task_id: "gk_timing" }, {}, norm.value, true);
    const timed = await proofModule.generateVerifiedProof(witness);
    console.log(`INFO  direct fullProve+verify time: ${timed.proveMs} ms`);
    check("proof generation comfortably under 60 s", timed.proveMs < 60000, `${timed.proveMs} ms`);

    // --- Trap classes (spec §6) ---
    await expectTrap("VK substitution (proof_vk != registered_vk)", { proof_vk: "0x" + "11".repeat(32) }, "VK_SUBSTITUTION");
    await expectTrap("VK not the platform hash (proof_vk == registered_vk != registered)", { registered_vk: "0x" + "22".repeat(32), proof_vk: "0x" + "22".repeat(32) }, "VK_SUBSTITUTION");
    await expectTrap("VK registered field substituted (registered_vk fake, proof_vk real)", { registered_vk: "0x" + "33".repeat(32) }, "VK_SUBSTITUTION");
    await expectTrap("balance below minimum", { public_balance: "999" }, "THRESHOLD_MISMATCH");
    await expectTrap("expired condition", { current_block: 8430000 }, "EXPIRED_CONDITION");
    await expectTrap("recipient mismatch", { condition_recipient: ADDR2 }, "RECIPIENT_MISMATCH");
    await expectTrap("amount over cap", { amount: "1001" }, "AMOUNT_OVERFLOW");

    // --- Proof reuse: resend the exact valid envelope ---
    r = await post(validEnv);
    check("reused proof_tx -> REJECT/PROOF_REUSED", r.status === 200 && r.json.decision === "REJECT" && r.json.reason_code === "PROOF_REUSED");
    check("reused proof_tx: no new proof attached", r.json.proof && Object.keys(r.json.proof).length === 0 && r.json.public_signals.length === 0);

    // --- Malformed / hostile inputs fail closed ---
    const malformed = taskEnvelope(validInput());
    delete malformed.input.amount;
    r = await post(malformed);
    check("missing field -> REJECT/MALFORMED_INPUT", r.status === 200 && r.json.decision === "REJECT" && r.json.reason_code === "MALFORMED_INPUT");
    r = await post(taskEnvelope(validInput()), { badSignature: true });
    check("task with bad signature -> 401", r.status === 401);
    r = await post({ type: "agent-games.unknown.v9" });
    check("unknown envelope type -> 400", r.status === 400);
    r = await post(null, { rawBody: "{not json" });
    check("non-JSON body with valid signature -> 400", r.status === 400);

    // --- Seen-set survives a restart ---
    child.kill("SIGTERM");
    await new Promise((res) => child.on("exit", res));
    child = startServer();
    check("server restarts", await waitForHealth());
    r = await post(validEnv);
    check("after restart, same proof_tx still PROOF_REUSED", r.status === 200 && r.json.reason_code === "PROOF_REUSED");
  } finally {
    child.kill("SIGTERM");
  }
  console.log(failures === 0 ? "\nALL TESTS PASSED" : `\n${failures} TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((err) => {
  console.error("test battery crashed:", err);
  process.exit(1);
});
