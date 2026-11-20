# SAFARI-1 — Protocol uncertainties & local design decisions

Everything in this file is something the public spec (GATEKEEPER_SPEC.md,
compiled from the platform's own pages on 2026-11-16) does **not** pin down,
plus the choice made locally for each. Nothing here was silently invented:
each item names the standard reading we implemented, where it is isolated
in the code, and how it gets confirmed (first live preflight / practice
tasks — a wrong guess fails loudly there, not silently).

## 1. HMAC digest & encoding — UNCONFIRMED
Spec §3 names the header (`x-agent-games-signature`) and the raw-body rule
but never states the digest or encoding.
**Implemented:** HMAC-SHA256 over the raw body, lowercase hex digest, bare
header value. Verification additionally tolerates a `sha256=` prefix and
uppercase hex. **Isolated in:** `src/config.js` (`hmacAlgorithm`,
`hmacEncoding`, env-overridable via `HMAC_ALGORITHM` / `HMAC_ENCODING`) and
`src/hmac.js`. **Confirm at:** preflight — a signature error there points
here first (after checking the secret itself).

## 2. Circuit input signals — DERIVED FROM THE WASM, not documented
The spec never lists the circuit's inputs. They were derived by probing the
official `gatekeeper.wasm`'s input-signal table (FNV-1a name hashes) and
cross-checked against `getInputSize()` = 13 and the exported VK's
`nPublic` = 13. The 13 inputs, in public-signal order as returned by
snarkjs (first entry is a circuit-computed output, see below):

`[commitment](output), registeredVkHash, proofVkHash, minimum,
publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
amount, maxTransfer, decision, taskId` — plus `salt`, the only **private**
input.

Semantics were verified experimentally with the official artifacts:
the circuit enforces `decision == 1` iff **all** conditions hold
(vk hashes equal, balance ≥ minimum, not expired, recipient matches,
amount ≤ cap) and `decision == 0` iff at least one fails. A wrong decision
in either direction fails the circuit's assert — a correct REJECT of a trap
is therefore provable, which is what earns the reliability bonus (spec §8).
Every generated proof is also verified locally against the exported VK
before it is returned.

The first public signal is a circuit-computed commitment whose exact
composition we did not fully determine (it did not vary with amount,
either vk hash, balance, block, or recipient in our tests; it presumably
binds `taskId` and the private `salt`). We pass it through untouched, as
snarkjs computes it.

## 3. `taskId` and `salt` provenance — UNCONFIRMED
Neither value appears in the documented envelope example (spec §2), yet
the circuit requires both. **Implemented** (`src/witness.js`): prefer, in
order, `input.taskId` / `input.task_id` / a numeric envelope `task_id`;
otherwise derive a deterministic field element as SHA-256 of the task_id
string mod p. Salt: `input.salt` / envelope `salt`, else `0`.
**Confirm at:** practice — if the platform sends real values, the direct
ones win automatically; if our derivation is wrong, the commitment output
won't match what the platform expects and its re-verification fails
loudly. This is the single most important thing to validate in practice.

## 4. VK encoding for VK_SUBSTITUTION rejects — DERIVED DESIGN DECISION
Spec §6 check 1 compares three values: `proof_vk == registered_vk ==
platform-registered hash`. The circuit only compares the two hashes it is
fed. Feeding both envelope values makes one trap sub-shape unprovable
(both fields substituted consistently → the circuit sees equal hashes and
a valid condition, so `decision=0` cannot be proven); feeding the platform
hash as `registeredVkHash` makes a different sub-shape unprovable
(`registered_vk` alone substituted). **Implemented:** for
VK_SUBSTITUTION rejects the server tries the platform-anchored encoding
first, then the envelope-literal one, and returns the first proof that
generates and verifies. All other outcomes use the envelope values (for
valid tasks they coincide with the platform hash anyway). The *decision*
is always made off-circuit by the deterministic engine; the encoding only
affects how that decision is proven. **Confirm at:** practice — once we
see which encoding the platform's re-verification accepts, drop the other.

## 5. Seen-set marking point — INTERPRETATION
Spec §6 check 3 requires a local seen-set but not when a value is
recorded. **Implemented:** a `proof_tx` is recorded when a task *reaches*
check 3 (i.e. after the VK and threshold checks pass), whatever later
checks decide. A task failing checks 1–2 does not consume its `proof_tx`.
Persistence is an append-only file (`SEEN_TX_PATH`); note that hosts with
ephemeral filesystems (Railway redeploys) can reset it — accepted risk
for this phase, revisit if the platform offers a state API.

## 6. Kurier request/response shapes — PARTLY UNCONFIRMED
The spec documents the submit endpoint and body (implemented verbatim in
`src/kurier.js`) and the job lifecycle names (Submitted → IncludedInBlock
→ Finalized). It does **not** document the job-status URL or response
field names. **Implemented:** `GET {KURIER_API_BASE}/api/v1/job-status/
<API_KEY>/<jobId>`, accepting `jobId|job_id|id` on submit and
`status|state` (top-level or under `data`) on poll — all isolated in
`src/kurier.js`. **Confirm at:** first real submission in practice.

Check 7 gating: the finalization gate is enforced only when
`KURIER_API_KEY` is set. Without a key the client is a stub and the proof
is returned in-band for the platform to re-verify (spec §7's model).
If finalization times out, the agent fails closed to REJECT with the
locally-invented reason_code `PROOF_NOT_FINALIZED`.

## 7. Locally-invented reason codes
The spec names six trap codes plus `VALID_CONDITION`. Fail-closed paths
it doesn't name use: `MALFORMED_INPUT` (missing/invalid fields),
`PROOF_NOT_FINALIZED` (item 6), `INTERNAL_ERROR` (proof generation failed
on an otherwise-approvable task → flipped to REJECT, never an unproven
APPROVE).

## 8. Error HTTP statuses — UNDOCUMENTED
Invalid/missing signature → **401** `{ok:false,error:"invalid_signature"}`
(still signed with our secret, per "sign every response"). Unparseable
JSON → 400. Unknown envelope `type` → 400. Decision responses are always
HTTP 200 per spec §5. None of the error statuses are in the public spec.

## 9. Timestamp validation — UNDOCUMENTED WINDOW
Spec §3 says to validate "the task signature and timestamp" without a
format or window. **Implemented:** if `issued_at` parses as a date and is
more than `TIMESTAMP_TOLERANCE_SECONDS` (default 300, 0 disables) from
server time, the request is rejected 401 `stale_timestamp`. Missing or
unparseable timestamps are not enforced. Revisit if practice shows the
platform's clock/format behaving differently.

## 10. Registered vkHash vs the zkey — COULD NOT BE RECOMPUTED
No documented algorithm maps the exported verification-key JSON to the
registered vkHash `0x6b79…d77b0`, so we could not recompute the hash
locally as a cross-check. The zkey is the platform's own artifact from
its official URL, and proofs generated from it verify against its
exported VK; the platform's re-verification in practice is the real test.
The hash is used as: (a) the third leg of decision check 1, and (b) the
`vk` field of the Kurier submit body, exactly as spec §7 prescribes.

## 11. Comparisons
VK hashes and amounts are compared as integers (BigInt), so case/leading
zeros cannot desynchronise the decision engine from the circuit (which
reduces mod the BN254 prime). Addresses are compared lowercase-normalised
off-circuit and as field elements in-circuit.
