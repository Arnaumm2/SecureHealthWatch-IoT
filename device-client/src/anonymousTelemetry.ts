import * as crypto from "crypto";
import { AnonymousCredential } from "./blindSignature";

function canonicalizeTelemetry(telemetry: unknown): string {
  return JSON.stringify(telemetry);
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

export function getCredentialId(credential: AnonymousCredential): string {
  return crypto
    .createHash("sha256")
    .update(canonicalizeCredential(credential))
    .digest("hex");
}

export function signTelemetryWithAnonymousKey(params: {
  telemetry: unknown;
  anonymousPrivateKey: string;
}): string {
  const signer = crypto.createSign("RSA-SHA256");

  signer.update(canonicalizeTelemetry(params.telemetry));
  signer.end();

  return signer.sign(params.anonymousPrivateKey, "base64");
}

export function buildAnonymousTelemetryPayload(params: {
  credential: AnonymousCredential;
  credentialSignature: string;
  anonymousPrivateKey: string;
}) {
  const telemetry = {
    h: 132,
    tp: 378,
    z: "E",
    r: 1,
  };

  const telemetrySignature = signTelemetryWithAnonymousKey({
    telemetry,
    anonymousPrivateKey: params.anonymousPrivateKey,
  });

  return {
    c: getCredentialId(params.credential),
    t: telemetry,
    s: telemetrySignature,
  };
}
