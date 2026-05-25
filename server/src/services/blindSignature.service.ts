import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";

const KEY_DIR = path.resolve(process.cwd(), "keys");
const PRIVATE_KEY_PATH = path.join(KEY_DIR, "blind-issuer-private-key.pem");
const PUBLIC_KEY_PATH = path.join(KEY_DIR, "blind-issuer-public-key.pem");

interface RsaPrivateJwk {
  kty: string;
  n: string;
  e: string;
  d: string;
}

interface RsaPublicJwk {
  kty: string;
  n: string;
  e: string;
}

function ensureBlindIssuerKeys() {
  if (!fs.existsSync(KEY_DIR)) {
    fs.mkdirSync(KEY_DIR, { recursive: true });
  }

  if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
    return;
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
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

  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey);
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey);

  console.log("Blind issuer RSA keys generated:");
  console.log(PRIVATE_KEY_PATH);
  console.log(PUBLIC_KEY_PATH);
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

function bigIntToHex(value: bigint): string {
  let hex = value.toString(16);

  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }

  return hex;
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

function loadPrivateJwk(): RsaPrivateJwk {
  ensureBlindIssuerKeys();

  const privatePem = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
  const privateKey = crypto.createPrivateKey(privatePem);

  return privateKey.export({ format: "jwk" }) as RsaPrivateJwk;
}

function loadPublicJwk(): RsaPublicJwk {
  ensureBlindIssuerKeys();

  const publicPem = fs.readFileSync(PUBLIC_KEY_PATH, "utf8");
  const publicKey = crypto.createPublicKey(publicPem);

  return publicKey.export({ format: "jwk" }) as RsaPublicJwk;
}

export function getBlindIssuerPublicKey() {
  const publicJwk = loadPublicJwk();

  return {
    kty: "RSA",
    n: publicJwk.n,
    e: publicJwk.e,
    alg: "RSA-BLIND-DEMO",
    use: "blind-signature",
  };
}

export function blindSignMessage(blindedMessageHex: string): string {
  const privateJwk = loadPrivateJwk();

  const n = base64UrlToBigInt(privateJwk.n);
  const d = base64UrlToBigInt(privateJwk.d);

  const blindedMessage = hexToBigInt(blindedMessageHex);

  if (blindedMessage <= 0n || blindedMessage >= n) {
    throw new Error("Invalid blinded message");
  }

  const blindSignature = modPow(blindedMessage, d, n);

  return bigIntToHex(blindSignature);
}