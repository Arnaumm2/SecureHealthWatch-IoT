import crypto from "crypto";
import fs from "fs";
import path from "path";

interface DeviceCertificatePayload {
  deviceId: string;
  devicePublicKey: string;
  manufacturer: string;
  issuedAt: string;
  expiresAt: string;
}

interface DeviceCertificate extends DeviceCertificatePayload {
  signature: string;
}

function ensureDir(dirPath: string) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
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

function generateRsaKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });
}

const manufacturerKeysDir = path.resolve(__dirname, "../keys");
const deviceCertsDir = path.resolve(__dirname, "../../device-client/certs");

ensureDir(manufacturerKeysDir);
ensureDir(deviceCertsDir);

const manufacturerPrivateKeyPath = path.join(
  manufacturerKeysDir,
  "manufacturer-private-key.pem"
);

const manufacturerPublicKeyPath = path.join(
  manufacturerKeysDir,
  "manufacturer-public-key.pem"
);

let manufacturerPrivateKey: string;
let manufacturerPublicKey: string;

if (
  fs.existsSync(manufacturerPrivateKeyPath) &&
  fs.existsSync(manufacturerPublicKeyPath)
) {
  manufacturerPrivateKey = fs.readFileSync(manufacturerPrivateKeyPath, "utf8");
  manufacturerPublicKey = fs.readFileSync(manufacturerPublicKeyPath, "utf8");
} else {
  const keys = generateRsaKeyPair();

  manufacturerPrivateKey = keys.privateKey;
  manufacturerPublicKey = keys.publicKey;

  fs.writeFileSync(manufacturerPrivateKeyPath, manufacturerPrivateKey);
  fs.writeFileSync(manufacturerPublicKeyPath, manufacturerPublicKey);
}

const deviceKeys = generateRsaKeyPair();

const devicePrivateKeyPath = path.join(deviceCertsDir, "device-private-key.pem");
const devicePublicKeyPath = path.join(deviceCertsDir, "device-public-key.pem");
const deviceCertificatePath = path.join(deviceCertsDir, "device-cert.json");

fs.writeFileSync(devicePrivateKeyPath, deviceKeys.privateKey);
fs.writeFileSync(devicePublicKeyPath, deviceKeys.publicKey);

const issuedAt = new Date();
const expiresAt = new Date();
expiresAt.setFullYear(expiresAt.getFullYear() + 1);

const payload: DeviceCertificatePayload = {
  deviceId: "watch-device-001",
  devicePublicKey: deviceKeys.publicKey,
  manufacturer: "SmartHealth Watch Inc.",
  issuedAt: issuedAt.toISOString(),
  expiresAt: expiresAt.toISOString(),
};

const signer = crypto.createSign("RSA-SHA256");
signer.update(canonicalizeCertificatePayload(payload));
signer.end();

const signature = signer.sign(manufacturerPrivateKey, "base64");

const certificate: DeviceCertificate = {
  ...payload,
  signature,
};

fs.writeFileSync(
  deviceCertificatePath,
  JSON.stringify(certificate, null, 2)
);

console.log("Manufacturer keys ready:");
console.log(manufacturerPublicKeyPath);
console.log("");
console.log("Device identity generated:");
console.log(devicePrivateKeyPath);
console.log(devicePublicKeyPath);
console.log(deviceCertificatePath);