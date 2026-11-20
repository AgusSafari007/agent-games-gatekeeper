"use strict";
// Deterministic decision engine for proof-gatekeeper tasks (spec §6).
// APPROVE only if EVERY check passes; any failure, malformed input, or
// uncertainty fails closed to REJECT. No language model anywhere near this.
//
// Check order follows the spec table; the first failing check names the
// reason_code. The proof_tx is recorded in the seen-set at the moment check 3
// is reached (i.e. after the VK and threshold checks pass) — see NOTES.md.
const config = require("./config");

const REASONS = {
  VALID: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  THRESHOLD: "THRESHOLD_MISMATCH",
  REUSED: "PROOF_REUSED",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  AMOUNT: "AMOUNT_OVERFLOW",
  // Local inventions for fail-closed paths the spec does not name (NOTES.md):
  MALFORMED: "MALFORMED_INPUT",
  NOT_FINALIZED: "PROOF_NOT_FINALIZED",
  INTERNAL: "INTERNAL_ERROR",
};

function toBigIntOrNull(value) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    return Number.isInteger(value) ? BigInt(value) : null;
  }
  if (typeof value === "string") {
    const v = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(v) || /^[0-9]+$/.test(v)) {
      try {
        return BigInt(v);
      } catch {
        return null;
      }
    }
  }
  return null;
}

function isAddressLike(value) {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value.trim());
}

// Validate + normalize the task `input` object. Returns {ok, value|error}.
function normalizeInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "input is not an object" };
  }
  const registeredVk = toBigIntOrNull(input.registered_vk);
  const proofVk = toBigIntOrNull(input.proof_vk);
  const minimum = toBigIntOrNull(input.minimum);
  const publicBalance = toBigIntOrNull(input.public_balance);
  const amount = toBigIntOrNull(input.amount);
  const maxTransfer = toBigIntOrNull(input.max_transfer);
  const expiryBlock = toBigIntOrNull(input.expiry_block);
  const currentBlock = toBigIntOrNull(input.current_block);

  if (registeredVk === null || proofVk === null) {
    return { ok: false, error: "registered_vk/proof_vk missing or not numeric" };
  }
  if (minimum === null || publicBalance === null) {
    return { ok: false, error: "minimum/public_balance missing or not numeric" };
  }
  if (amount === null || maxTransfer === null) {
    return { ok: false, error: "amount/max_transfer missing or not numeric" };
  }
  if (expiryBlock === null || currentBlock === null) {
    return { ok: false, error: "expiry_block/current_block missing or not numeric" };
  }
  if (!isAddressLike(input.recipient) || !isAddressLike(input.condition_recipient)) {
    return { ok: false, error: "recipient/condition_recipient missing or not an address" };
  }
  if (typeof input.proof_tx !== "string" || input.proof_tx.trim() === "") {
    return { ok: false, error: "proof_tx missing" };
  }
  return {
    ok: true,
    value: {
      registeredVk,
      proofVk,
      minimum,
      publicBalance,
      amount,
      maxTransfer,
      expiryBlock,
      currentBlock,
      recipient: input.recipient.trim().toLowerCase(),
      conditionRecipient: input.condition_recipient.trim().toLowerCase(),
      proofTx: input.proof_tx.trim(),
    },
  };
}

const PLATFORM_VK = toBigIntOrNull(config.registeredVkHash);

// Pure field checks 1,2,4,5,6 (check 3 needs the seen-store, check 7 is the
// Kurier finalization gate handled by the caller). Returns the first failing
// reason or null. `stage` controls which checks run: "preSeen" = 1,2;
// "postSeen" = 4,5,6.
function checkFields(v, stage) {
  if (stage === "preSeen") {
    // 1. proof_vk equals registered_vk AND the platform-registered VK hash.
    if (v.proofVk !== v.registeredVk || v.registeredVk !== PLATFORM_VK) {
      return REASONS.VK;
    }
    // 2. public_balance >= minimum.
    if (v.publicBalance < v.minimum) return REASONS.THRESHOLD;
    return null;
  }
  // 4. Not expired: current_block < expiry_block.
  if (!(v.currentBlock < v.expiryBlock)) return REASONS.EXPIRED;
  // 5. recipient equals condition_recipient.
  if (v.recipient !== v.conditionRecipient) return REASONS.RECIPIENT;
  // 6. amount <= max_transfer.
  if (v.amount > v.maxTransfer) return REASONS.AMOUNT;
  return null;
}

// Full decision for a normalized task. `seenStore` must expose has()/add().
function decide(v, seenStore) {
  const pre = checkFields(v, "preSeen");
  if (pre) return { decision: "REJECT", reason_code: pre, provable: true };
  // 3. proof_tx not seen before. Reaching this check records the value.
  if (!seenStore.add(v.proofTx)) {
    return { decision: "REJECT", reason_code: REASONS.REUSED, provable: false };
  }
  const post = checkFields(v, "postSeen");
  if (post) return { decision: "REJECT", reason_code: post, provable: true };
  return { decision: "APPROVE", reason_code: REASONS.VALID, provable: true };
}

module.exports = { REASONS, normalizeInput, decide, toBigIntOrNull };
