"use strict";
// Builds the gatekeeper circuit witness inputs from a task envelope.
//
// The circuit's 13 input signals were DERIVED from the official wasm (the
// public spec never lists them) and their semantics verified experimentally:
// the circuit enforces decision == 1 iff every condition holds, and
// decision == 0 iff at least one fails. All inputs except `salt` are public;
// the first public signal is a circuit-computed commitment (see NOTES.md).
//
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//   decision, taskId, salt (private)
//
// ⚠️ UNCONFIRMED: `taskId` and `salt` do not appear in the documented
// envelope example (spec §2). Derivation below prefers values actually
// present in the envelope; the fallbacks are deterministic guesses that
// practice mode must confirm or refute (a wrong binding changes the
// commitment output, so the platform's re-verification fails loudly).
const crypto = require("crypto");
const { toBigIntOrNull } = require("./decision");

const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function fieldString(big) {
  const v = ((big % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME;
  return v.toString();
}

function deriveTaskId(envelope, input) {
  const direct =
    toBigIntOrNull(input && input.taskId) ??
    toBigIntOrNull(input && input.task_id) ??
    toBigIntOrNull(envelope && envelope.task_id);
  if (direct !== null) return fieldString(direct);
  // Fallback: deterministic field element from the task_id string.
  const raw = String((envelope && envelope.task_id) || "");
  const digest = crypto.createHash("sha256").update(raw, "utf8").digest("hex");
  return fieldString(BigInt("0x" + digest));
}

function deriveSalt(envelope, input) {
  const direct =
    toBigIntOrNull(input && input.salt) ?? toBigIntOrNull(envelope && envelope.salt);
  if (direct !== null) return fieldString(direct);
  return "0";
}

// `v` is the normalized input from decision.normalizeInput; `approve` is the
// field-check outcome. Returns the witness input object for snarkjs.
//
// `opts.registeredVkHashOverride` replaces the envelope's registered_vk as
// the circuit's registeredVkHash input. The server uses this for
// VK_SUBSTITUTION rejects: when a trap substitutes BOTH vk fields
// consistently, the envelope-literal encoding makes a decision=0 proof
// impossible (the circuit sees two equal hashes and a valid condition), so
// the proof is anchored to the platform-registered hash instead — the
// substantive fact check 1 of spec §6 actually asserts. See NOTES.md.
function buildWitnessInput(envelope, input, v, approve, opts = {}) {
  return {
    registeredVkHash: fieldString(opts.registeredVkHashOverride ?? v.registeredVk),
    proofVkHash: fieldString(v.proofVk),
    minimum: v.minimum.toString(),
    publicBalance: v.publicBalance.toString(),
    expiryBlock: v.expiryBlock.toString(),
    currentBlock: v.currentBlock.toString(),
    recipient: fieldString(BigInt(v.recipient)),
    conditionRecipient: fieldString(BigInt(v.conditionRecipient)),
    amount: v.amount.toString(),
    maxTransfer: v.maxTransfer.toString(),
    decision: approve ? "1" : "0",
    taskId: deriveTaskId(envelope, input),
    salt: deriveSalt(envelope, input),
  };
}

module.exports = { buildWitnessInput, deriveTaskId, deriveSalt, FIELD_PRIME };
