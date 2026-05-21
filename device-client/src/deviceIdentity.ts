import crypto from "crypto";
import fs from "fs";
import path from "path";

export function loadDeviceCertificate() {
  const certPath = path.resolve(process.cwd(), "certs/device-cert.json");
  const raw = fs.readFileSync(certPath, "utf8");

  return JSON.parse(raw);
}

export function loadDevicePrivateKey() {
  const privateKeyPath = path.resolve(
    process.cwd(),
    "certs/device-private-key.pem"
  );

  return fs.readFileSync(privateKeyPath, "utf8");
}

export function signNonceWithDevicePrivateKey(nonce: string): string {
  const privateKey = loadDevicePrivateKey();

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(nonce);
  signer.end();

  return signer.sign(privateKey, "base64");
}