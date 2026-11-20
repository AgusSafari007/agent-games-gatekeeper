"use strict";
// HMAC signing/verification for the Agent Games protocol (spec §3).
// The signature is an HMAC over the RAW body bytes, carried in the
// `x-agent-games-signature` header, in both directions.
//
// ⚠️ The public spec does not state the digest or encoding. The single
// config point is config.hmacAlgorithm / config.hmacEncoding
// (default: HMAC-SHA256, lowercase hex). Verification additionally tolerates
// an optional "sha256=" prefix and uppercase hex so a format surprise at
// preflight time degrades gracefully instead of hard-failing; signing always
// emits the canonical configured form. See NOTES.md.
const crypto = require("crypto");
const config = require("./config");

function sign(rawBody) {
  return crypto
    .createHmac(config.hmacAlgorithm, config.hmacSecret)
    .update(rawBody)
    .digest(config.hmacEncoding);
}

function normalizePresented(value) {
  if (typeof value !== "string") return "";
  let v = value.trim();
  const eq = v.indexOf("=");
  // Tolerate a "sha256=<digest>" style prefix.
  if (eq > 0 && /^[a-z0-9-]+$/i.test(v.slice(0, eq))) v = v.slice(eq + 1);
  return v.toLowerCase();
}

function verify(rawBody, presentedHeader) {
  const expected = sign(rawBody);
  const presented = normalizePresented(presentedHeader);
  if (!presented) return false;
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(presented, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { sign, verify };
