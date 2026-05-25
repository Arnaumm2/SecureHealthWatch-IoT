import * as crypto from "crypto";

interface BlindIssuerPublicKey {
  kty: string;
  n: string;
  e: string;
  alg: string;
  use: string;
}

export interface AnonymousCredential {
  anonymousPublicKey: string;
  scope: "send-health-telemetry";
  issuedFor: "anonymous-smartwatch";
  expiresAt: string;
  nonce: string;
}

export interface BlindedCredential {
  credential: AnonymousCredential;
  message: bigint;
  blindingFactor: bigint;
  blindedMessageHex: string;
  issuerN: bigint;
  issuerE: bigint;
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

function bigIntToHex(value: bigint): string {
  let hex = value.toString(16);

  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }

  return hex;
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

function egcd(a: bigint, b: bigint): { g: bigint; x: bigint; y: bigint } {
  if (a === 0n) {
    return { g: b, x: 0n, y: 1n };
  }

  const result = egcd(b % a, a);

  return {
    g: result.g,
    x: result.y - (b / a) * result.x,
    y: result.x,
  };
}

function modInv(a: bigint, m: bigint): bigint {
  const { g, x } = egcd(a, m);

  if (g !== 1n) {
    throw new Error("Modular inverse does not exist");
  }

  return ((x % m) + m) % m;
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a;
  let y = b;

  while (y !== 0n) {
    const temp = y;
    y = x % y;
    x = temp;
  }

  return x;
}

function randomBigIntLessThan(n: bigint): bigint {
  const byteLength = Math.ceil(n.toString(16).length / 2);

  while (true) {
    const random = BigInt("0x" + crypto.randomBytes(byteLength).toString("hex"));

    if (random > 1n && random < n) {
      return random;
    }
  }
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

export function generateAnonymousKeyPair() {
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

export function createAnonymousCredential(
  anonymousPublicKey: string
): AnonymousCredential {
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  return {
    anonymousPublicKey,
    scope: "send-health-telemetry",
    issuedFor: "anonymous-smartwatch",
    expiresAt,
    nonce: crypto.randomBytes(16).toString("hex"),
  };
}

export function blindCredential(
  credential: AnonymousCredential,
  issuerPublicKey: BlindIssuerPublicKey
): BlindedCredential {
  const n = base64UrlToBigInt(issuerPublicKey.n);
  const e = base64UrlToBigInt(issuerPublicKey.e);

  const message = hashCredentialToBigInt(credential);

  let r: bigint;

  do {
    r = randomBigIntLessThan(n);
  } while (gcd(r, n) !== 1n);

  const blindedMessage = (message * modPow(r, e, n)) % n;

  return {
    credential,
    message,
    blindingFactor: r,
    blindedMessageHex: bigIntToHex(blindedMessage),
    issuerN: n,
    issuerE: e,
  };
}

export function unblindSignature(
  blindSignatureHex: string,
  blindingFactor: bigint,
  issuerN: bigint
): string {
  const blindSignature = hexToBigInt(blindSignatureHex);
  const rInverse = modInv(blindingFactor, issuerN);

  const signature = (blindSignature * rInverse) % issuerN;

  return bigIntToHex(signature);
}

export function verifyUnblindedSignature(params: {
  message: bigint;
  signatureHex: string;
  issuerN: bigint;
  issuerE: bigint;
}): boolean {
  const signature = hexToBigInt(params.signatureHex);

  const recoveredMessage = modPow(signature, params.issuerE, params.issuerN);

  return recoveredMessage === params.message;
}