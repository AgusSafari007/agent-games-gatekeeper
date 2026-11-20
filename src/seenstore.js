"use strict";
// Persistent seen-set of proof_tx values (spec §6 check 3, PROOF_REUSED).
// Append-only text file, one proof_tx per line, loaded at startup and
// appended synchronously on first sight, so the set survives restarts.
// NOTE: on hosts with an ephemeral filesystem (e.g. Railway redeploys) the
// file can reset; that risk is recorded in NOTES.md.
const fs = require("fs");
const path = require("path");
const config = require("./config");

class SeenStore {
  constructor(filePath = config.seenTxPath) {
    this.filePath = filePath;
    this.set = new Set();
    try {
      const raw = fs.readFileSync(filePath, "utf8");
      for (const line of raw.split("\n")) {
        const v = line.trim().toLowerCase();
        if (v) this.set.add(v);
      }
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
  }

  has(proofTx) {
    return this.set.has(String(proofTx).toLowerCase());
  }

  // Returns true if the value was newly recorded, false if already present.
  add(proofTx) {
    const v = String(proofTx).toLowerCase();
    if (this.set.has(v)) return false;
    this.set.add(v);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.appendFileSync(this.filePath, v + "\n");
    return true;
  }

  get size() {
    return this.set.size;
  }
}

module.exports = SeenStore;
