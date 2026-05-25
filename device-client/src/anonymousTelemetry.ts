import * as crypto from "crypto";
import { AnonymousCredential } from "./blindSignature";

function canonicalizeTelemetry(telemetry: unknown): string {
  return JSON.stringify(telemetry);
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
    heartRate: 132,
    temperature: 37.8,
    zone: "Eixample",
    risk: "high",
    sentAt: new Date().toISOString(),
  };

  const telemetrySignature = signTelemetryWithAnonymousKey({
    telemetry,
    anonymousPrivateKey: params.anonymousPrivateKey,
  });

  return {
    credential: params.credential,
    credentialSignature: params.credentialSignature,
    telemetry,
    telemetrySignature,
  };
}