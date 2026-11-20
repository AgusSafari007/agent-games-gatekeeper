"use strict";
// SAFARI-1 — Proof Gatekeeper agent for zkVerify Agent Games Season 01.
//
// Plain node:http service implementing the protocol in GATEKEEPER_SPEC.md:
//   - POST <AGENT_PATH>  signed task envelopes (preflight + proof-gatekeeper)
//   - GET  /health       liveness
// Every response is HMAC-signed over its raw body (spec §3). Inbound
// signatures are verified over the raw request body BEFORE any JSON parsing.
// All gatekeeper handling is serialized through a queue so the proof_tx
// seen-set and proof generation never interleave.
const http = require("http");
const config = require("./config");
const hmac = require("./hmac");
const SeenStore = require("./seenstore");
const { REASONS, normalizeInput, decide } = require("./decision");
const { buildWitnessInput } = require("./witness");
const proofModule = require("./proof");
const kurier = require("./kurier");

const seenStore = new SeenStore();

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    "content-type": "application/json",
    [config.hmacHeader]: hmac.sign(body),
  });
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > 1024 * 1024) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// Spec §3 also asks for timestamp validation; no window/format is documented,
// so this only enforces when issued_at parses and a tolerance is configured.
function timestampAcceptable(envelope) {
  if (!config.timestampToleranceSeconds) return true;
  if (!envelope || typeof envelope.issued_at !== "string") return true;
  const t = Date.parse(envelope.issued_at);
  if (Number.isNaN(t)) return true;
  return Math.abs(Date.now() - t) <= config.timestampToleranceSeconds * 1000;
}

async function handleGatekeeperTask(envelope) {
  const echoTx =
    envelope.input && typeof envelope.input.proof_tx === "string"
      ? envelope.input.proof_tx
      : null;
  const normalized = normalizeInput(envelope.input);
  if (!normalized.ok) {
    log("task rejected as malformed:", normalized.error);
    return {
      decision: "REJECT",
      reason_code: REASONS.MALFORMED,
      proof: {},
      public_signals: [],
      proof_tx: echoTx,
    };
  }
  const v = normalized.value;
  const outcome = decide(v, seenStore);
  const response = {
    decision: outcome.decision,
    reason_code: outcome.reason_code,
    proof: {},
    public_signals: [],
    proof_tx: v.proofTx,
  };

  if (outcome.provable) {
    try {
      // For VK_SUBSTITUTION rejects there are two defensible encodings of
      // the circuit's registeredVkHash input (envelope-literal vs anchored
      // to the platform-registered hash); each makes a different trap
      // sub-shape provable, so try the platform-anchored encoding first and
      // fall back to the envelope-literal one. Everywhere else the envelope
      // values are the only encoding (and for valid tasks they coincide).
      // See NOTES.md — practice mode should pin which one the platform
      // expects, after which the other can be dropped.
      const witnessVariants =
        outcome.reason_code === REASONS.VK
          ? [
              buildWitnessInput(envelope, envelope.input, v, false, {
                registeredVkHashOverride:
                  require("./decision").toBigIntOrNull(config.registeredVkHash),
              }),
              buildWitnessInput(envelope, envelope.input, v, false),
            ]
          : [
              buildWitnessInput(
                envelope,
                envelope.input,
                v,
                outcome.decision === "APPROVE"
              ),
            ];
      let proved = null;
      let lastErr = null;
      for (const witness of witnessVariants) {
        try {
          proved = await proofModule.generateVerifiedProof(witness);
          break;
        } catch (err) {
          lastErr = err;
        }
      }
      if (!proved) throw lastErr || new Error("proof generation failed");
      const { proof, publicSignals, proveMs } = proved;
      response.proof = proof;
      response.public_signals = publicSignals;
      log(
        `task ${envelope.task_id || "?"}: ${outcome.decision}/${outcome.reason_code}` +
          ` proof generated+verified in ${proveMs} ms`
      );
    } catch (err) {
      log("proof generation failed:", err.message);
      if (outcome.decision === "APPROVE") {
        // Fail closed: an approval we cannot prove must not stand.
        response.decision = "REJECT";
        response.reason_code = REASONS.INTERNAL;
        response.proof = {};
        response.public_signals = [];
      }
      // A trap REJECT keeps its reason_code; it just carries no proof.
    }
  } else {
    log(`task ${envelope.task_id || "?"}: ${outcome.decision}/${outcome.reason_code} (no proof)`);
  }

  // Spec §6 check 7: before an APPROVE stands, the referenced proof must be
  // verified and finalized on zkVerify. Enforced only when Kurier is
  // configured; otherwise the in-band proof is re-verified by the platform.
  if (response.decision === "APPROVE" && kurier.enabled()) {
    try {
      const { jobId } = await kurier.submitProof(response.proof, response.public_signals);
      const finalized = await kurier.waitForFinalized(jobId);
      if (!finalized) throw new Error("Kurier job did not reach Finalized in time");
      log(`task ${envelope.task_id || "?"}: Kurier job ${jobId} finalized`);
    } catch (err) {
      log("Kurier finalization gate failed:", err.message);
      response.decision = "REJECT";
      response.reason_code = REASONS.NOT_FINALIZED;
    }
  }
  return response;
}

async function handleProtocol(req, res) {
  let raw;
  try {
    raw = await readRawBody(req);
  } catch {
    return sendJson(res, 413, { ok: false, error: "body_too_large" });
  }
  // Verify BEFORE parsing (spec §3).
  if (!hmac.verify(raw, req.headers[config.hmacHeader])) {
    return sendJson(res, 401, { ok: false, error: "invalid_signature" });
  }
  let envelope;
  try {
    envelope = JSON.parse(raw.toString("utf8"));
  } catch {
    return sendJson(res, 400, { ok: false, error: "invalid_json" });
  }
  if (!timestampAcceptable(envelope)) {
    return sendJson(res, 401, { ok: false, error: "stale_timestamp" });
  }
  if (envelope && envelope.type === config.preflightType) {
    return sendJson(res, 200, { ok: true, protocolVersion: config.protocolVersion });
  }
  if (envelope && envelope.type === config.gatekeeperType) {
    const response = await handleGatekeeperTask(envelope);
    return sendJson(res, 200, response);
  }
  return sendJson(res, 400, { ok: false, error: "unknown_type" });
}

// Serialize protocol handling: seen-set updates and proving stay race-free.
let queue = Promise.resolve();
function enqueue(fn) {
  const run = queue.then(fn, fn);
  queue = run.catch(() => {});
  return run;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (req.method === "GET" && url.pathname === "/health") {
    return sendJson(res, 200, {
      ok: true,
      service: "safari-1-gatekeeper",
      protocolVersion: config.protocolVersion,
    });
  }
  if (req.method === "POST" && url.pathname === config.agentPath) {
    enqueue(() => handleProtocol(req, res)).catch((err) => {
      log("unhandled handler error:", err && err.message);
      if (!res.headersSent) sendJson(res, 500, { ok: false, error: "internal_error" });
    });
    return;
  }
  return sendJson(res, 404, { ok: false, error: "not_found" });
});

if (require.main === module) {
  if (config.hmacSecretIsPlaceholder) {
    log(
      "WARNING: AGENT_GAMES_HMAC_SECRET is not set — using the local placeholder." +
        " Live preflight will fail until the dashboard-issued secret is configured."
    );
  }
  log(`Kurier: ${kurier.enabled() ? "enabled" : "disabled (stub — no KURIER_API_KEY)"}`);
  log(`Seen-set: ${seenStore.size} proof_tx loaded from ${config.seenTxPath}`);
  server.listen(config.port, () => {
    log(`SAFARI-1 gatekeeper listening on :${config.port} (handler path ${config.agentPath}, health /health)`);
  });
}

module.exports = { server, handleGatekeeperTask };
