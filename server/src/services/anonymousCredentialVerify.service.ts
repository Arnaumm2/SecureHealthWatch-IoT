import * as crypto from "crypto";
import {
  getBlindIssuerPublicKey,
} from "./blindSignature.service";

export interface AnonymousCredential {
  anonymousPublicKey: string;
  scope: "send-health-telemetry";
  issuedFor: "anonymous-smartwatch";
  expiresAt: string;
  nonce: string;
}

function base64UrlToBigInt(value: string): bigint {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    "="
  );

  const hex = Buffer.from(padded, "base64").toString("hex");

  return BigInt("0x" + hex);
}

function hexToBigInt(hex: string): bigint {
  return BigInt("0x" + hex);
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;

  while (e > 0n) {
    if (e % 2n === 1n) {
      result = (result * b) % modulus;
    }

    e = e / 2n;
    b = (b * b) % modulus;
  }

  return result;
}

function canonicalizeCredential(credential: AnonymousCredential): string {
  return JSON.stringify({
    anonymousPublicKey: credential.anonymousPublicKey,
    scope: credential.scope,
    issuedFor: credential.issuedFor,
    expiresAt: credential.expiresAt,
    nonce: credential.nonce,
  });
}

function hashCredentialToBigInt(credential: AnonymousCredential): bigint {
  const canonical = canonicalizeCredential(credential);

  const digest = crypto
    .createHash("sha256")
    .update(canonical)
    .digest("hex");

  return BigInt("0x" + digest);
}

function canonicalizeTelemetry(telemetry: unknown): string {
  return JSON.stringify(telemetry);
}

export function verifyCredentialSignature(params: {
  credential: AnonymousCredential;
  credentialSignature: string;
}): boolean {
  const publicKey = getBlindIssuerPublicKey();

  const n = base64UrlToBigInt(publicKey.n);
  const e = base64UrlToBigInt(publicKey.e);

  const expectedMessage = hashCredentialToBigInt(params.credential);
  const signature = hexToBigInt(params.credentialSignature);

  const recoveredMessage = modPow(signature, e, n);

  return recoveredMessage === expectedMessage;
}

export function verifyCredentialFields(credential: AnonymousCredential): void {
  if (credential.scope !== "send-health-telemetry") {
    throw new Error("Invalid credential scope");
  }

  if (credential.issuedFor !== "anonymous-smartwatch") {
    throw new Error("Invalid credential type");
  }

  if (Date.now() > new Date(credential.expiresAt).getTime()) {
    throw new Error("Anonymous credential expired");
  }
}

export function verifyTelemetrySignature(params: {
  telemetry: unknown;
  telemetrySignature: string;
  anonymousPublicKey: string;
}): boolean {
  const verifier = crypto.createVerify("RSA-SHA256");

  verifier.update(canonicalizeTelemetry(params.telemetry));
  verifier.end();

  return verifier.verify(
    params.anonymousPublicKey,
    params.telemetrySignature,
    "base64"
  );
}