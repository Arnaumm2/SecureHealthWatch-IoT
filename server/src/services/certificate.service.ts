import crypto from "crypto";
import fs from "fs";
import path from "path";

export interface DeviceCertificatePayload {
  deviceId: string;
  devicePublicKey: string;
  manufacturer: string;
  issuedAt: string;
  expiresAt: string;
}

export interface DeviceCertificate extends DeviceCertificatePayload {
  signature: string;
}

function canonicalizeCertificatePayload(payload: DeviceCertificatePayload): string {
  return JSON.stringify({
    deviceId: payload.deviceId,
    devicePublicKey: payload.devicePublicKey,
    manufacturer: payload.manufacturer,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
  });
}

export function getCertificatePayload(
  certificate: DeviceCertificate
): DeviceCertificatePayload {
  return {
    deviceId: certificate.deviceId,
    devicePublicKey: certificate.devicePublicKey,
    manufacturer: certificate.manufacturer,
    issuedAt: certificate.issuedAt,
    expiresAt: certificate.expiresAt,
  };
}

export function verifyManufacturerSignature(
  certificate: DeviceCertificate
): boolean {
  const publicKeyPath =
    process.env.MANUFACTURER_PUBLIC_KEY_PATH ||
    "../manufacturer/keys/manufacturer-public-key.pem";

  const resolvedPath = path.resolve(process.cwd(), publicKeyPath);
  const manufacturerPublicKey = fs.readFileSync(resolvedPath, "utf8");

  const payload = getCertificatePayload(certificate);
  const payloadString = canonicalizeCertificatePayload(payload);

  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(payloadString);
  verifier.end();

  return verifier.verify(
    manufacturerPublicKey,
    certificate.signature,
    "base64"
  );
}

export function verifyCertificateExpiration(
  certificate: DeviceCertificate
): boolean {
  const now = Date.now();
  const issuedAt = new Date(certificate.issuedAt).getTime();
  const expiresAt = new Date(certificate.expiresAt).getTime();

  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt)) {
    return false;
  }

  return issuedAt <= now && now < expiresAt;
}

export function verifyDeviceNonceSignature(params: {
  nonce: string;
  signature: string;
  devicePublicKey: string;
}): boolean {
  const verifier = crypto.createVerify("RSA-SHA256");
  verifier.update(params.nonce);
  verifier.end();

  return verifier.verify(
    params.devicePublicKey,
    params.signature,
    "base64"
  );
}

export function getCertificateFingerprint(
  certificate: DeviceCertificate
): string {
  const payload = JSON.stringify(certificate);

  return crypto
    .createHash("sha256")
    .update(payload)
    .digest("hex");
}