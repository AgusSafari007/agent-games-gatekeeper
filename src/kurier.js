"use strict";
// Kurier submission client (spec §7) — the platform-recommended path for
// getting the agent's own proof verified + finalized on zkVerify (spec §6
// check 7).
//
// The spec documents the SUBMIT endpoint and body, and the job lifecycle
// (Submitted → IncludedInBlock → Finalized). It does NOT document the
// job-status URL or response field names; those are isolated here and in
// config (KURIER_API_BASE) and flagged in NOTES.md as unconfirmed.
//
// With KURIER_API_KEY unset this module is a stub: no network calls, and
// callers treat finalization as "not applicable" (the proof is returned in
// the response body and the platform re-verifies it against its own key).
const config = require("./config");

function enabled() {
  return Boolean(config.kurierApiKey);
}

async function submitProof(proof, publicSignals) {
  if (!enabled()) return { submitted: false, dryRun: true };
  const url = `${config.kurierApiBase}/api/v1/submit-proof/${config.kurierApiKey}`;
  const body = {
    proofType: "groth16",
    vkRegistered: true,
    proofOptions: { library: "snarkjs", curve: "bn128" },
    proofData: { proof, publicSignals, vk: config.registeredVkHash },
  };
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`Kurier submit failed: HTTP ${res.status}`);
  }
  const data = await res.json();
  // ⚠️ UNCONFIRMED response shape: accept the common field spellings.
  const jobId = data.jobId || data.job_id || data.id || (data.data && data.data.jobId);
  if (!jobId) throw new Error("Kurier submit response carried no job id");
  return { submitted: true, jobId };
}

async function jobStatus(jobId) {
  // ⚠️ UNCONFIRMED URL shape — see header comment.
  const url = `${config.kurierApiBase}/api/v1/job-status/${config.kurierApiKey}/${jobId}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Kurier job-status failed: HTTP ${res.status}`);
  const data = await res.json();
  // ⚠️ UNCONFIRMED field names: accept common spellings.
  const status =
    data.status || data.state || (data.data && (data.data.status || data.data.state)) || "";
  return String(status);
}

// Poll until the job reaches "Finalized" or the timeout elapses.
// Returns true only on Finalized (spec §7: only a Finalized result counts).
async function waitForFinalized(jobId, timeoutMs = config.kurierFinalizeTimeoutMs) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const status = await jobStatus(jobId);
    if (/final/i.test(status)) return true;
    if (Date.now() + config.kurierPollIntervalMs > deadline) return false;
    await new Promise((r) => setTimeout(r, config.kurierPollIntervalMs));
  }
}

module.exports = { enabled, submitProof, jobStatus, waitForFinalized };
