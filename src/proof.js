"use strict";
// Groth16 proof generation with snarkjs from the official circuit artifacts
// (spec §7), plus local verification against the verification key exported
// from the zkey. Measured on this VM: ~0.25–0.8 s per proof — far inside the
// 60 s deadline (spec §1).
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const config = require("./config");

const wasmPath = path.join(config.circuitsDir, "gatekeeper.wasm");
const zkeyPath = path.join(config.circuitsDir, "gatekeeper_final.zkey");
const vkPath = path.join(config.circuitsDir, "verification_key.json");

let cachedVk = null;
function verificationKey() {
  if (!cachedVk) {
    cachedVk = JSON.parse(fs.readFileSync(vkPath, "utf8"));
  }
  return cachedVk;
}

// Returns { proof, publicSignals, proveMs }.
async function generateProof(witnessInput) {
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witnessInput,
    wasmPath,
    zkeyPath
  );
  return { proof, publicSignals, proveMs: Date.now() - t0 };
}

async function verifyProof(proof, publicSignals) {
  return snarkjs.groth16.verify(verificationKey(), publicSignals, proof);
}

// Generate and self-verify. Throws if generation fails or the proof does
// not verify against the exported VK — callers fail closed.
async function generateVerifiedProof(witnessInput) {
  const out = await generateProof(witnessInput);
  const ok = await verifyProof(out.proof, out.publicSignals);
  if (!ok) throw new Error("generated proof failed local verification");
  return out;
}

module.exports = { generateProof, verifyProof, generateVerifiedProof, verificationKey };
