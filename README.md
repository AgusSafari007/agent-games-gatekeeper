# SAFARI-1 — Proof Gatekeeper Agent

An autonomous agent for the **Proof Gatekeeper** event of
[zkVerify Agent Games](https://agentgames.zkverify.io) Season 01, built for
participant **@hayyu001**.

The platform sends this agent signed payment-approval tasks. For each task
the agent decides **APPROVE** or **REJECT** with a deterministic rules
engine — and proves its decision correct with a **Groth16 zero-knowledge
proof** generated locally from the official `gatekeeper` circuit. A proof
can verify perfectly while authorizing the wrong action, so the agent
checks *what* was proven, not only *that* it verified — and it fails
closed: on any doubt, malformed input, or internal error, it rejects.

## How it works

```
platform ──POST signed envelope──▶  /agent
                                   │ 1. Verify x-agent-games-signature
                                   │    HMAC over the RAW body (before parsing)
                                   │ 2. Route: preflight → signed {ok:true,…}
                                   │         gatekeeper task → decision engine
                                   │ 3. Six checks (spec order):
                                   │    vk match · balance ≥ minimum ·
                                   │    proof_tx unseen · not expired ·
                                   │    recipient match · amount ≤ cap
                                   │ 4. Generate a Groth16 proof of the
                                   │    decision (decision=1 iff all checks
                                   │    pass, decision=0 iff one fails —
                                   │    the circuit enforces exactly this)
                                   │ 5. Optional: submit via Kurier and wait
                                   │    for zkVerify finalization
                                   └─ signed JSON response ◀──┘
```

- **Decisions** are deterministic code (`src/decision.js`) — never a
  language model. Reason codes: `VALID_CONDITION`, `VK_SUBSTITUTION`,
  `THRESHOLD_MISMATCH`, `PROOF_REUSED`, `EXPIRED_CONDITION`,
  `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`.
- **Replay protection**: a persistent, append-only seen-set of `proof_tx`
  values (`src/seenstore.js`) survives restarts.
- **Proofs**: snarkjs + the official circuit artifacts in `circuits/`
  (`gatekeeper.wasm`, `gatekeeper_final.zkey`, and the verification key
  exported from the zkey). Every proof is verified locally before being
  returned. Generation takes ~0.3–1 s — far inside the 60-second deadline.
- **Authentication**: HMAC over the raw body in both directions
  (`x-agent-games-signature`). The secret exists only as the
  `AGENT_GAMES_HMAC_SECRET` environment variable; it is issued by the
  platform dashboard (Rotate Secret) and never touches this repo.

## Run locally

```bash
npm install
AGENT_GAMES_HMAC_SECRET=local-dev npm start   # http://localhost:3000
# health:  GET  /health
# handler: POST /agent   (path configurable via AGENT_PATH)
```

## Test

```bash
npm test
```

Spawns the real server with a dummy secret and replays synthetic signed
envelopes: preflight, a valid task, every trap class, bad signatures,
malformed input, `proof_tx` reuse (including across a server restart),
and local verification of every returned proof.

## Configuration

See `.env.example`. Key variables: `AGENT_GAMES_HMAC_SECRET` (required
live), `KURIER_API_KEY` (optional; enables the submit-and-finalize gate),
`PORT`, `AGENT_PATH`, `SEEN_TX_PATH`.

## Honest fine print

The public protocol documentation leaves a few details unspecified (HMAC
digest/encoding, where the circuit's `taskId`/`salt` inputs come from,
Kurier's job-status shape). Each is implemented as the most standard
reading, isolated in one config point, and written up in
**[NOTES.md](NOTES.md)** — to be confirmed against live practice tasks,
where a wrong guess fails loudly rather than silently.

## Layout

```
src/        server, HMAC, decision engine, witness builder, proof, Kurier
circuits/   official gatekeeper artifacts + exported verification key
test/       the local test battery (npm test)
```
