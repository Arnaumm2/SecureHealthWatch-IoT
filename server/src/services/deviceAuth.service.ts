import * as crypto from "crypto";

import { Device } from "../models/Device.model";
import { DeviceChallenge } from "../models/DeviceChallenge.model";
import { DeviceAuthSession } from "../models/DeviceAuthSession.model";
import { createDeviceAccessToken } from "./token.service";

import {
  DeviceCertificate,
  verifyManufacturerSignature,
  verifyCertificateExpiration,
  verifyDeviceNonceSignature,
  getCertificateFingerprint,
} from "./certificate.service";

const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const DEVICE_AUTH_TTL_MS = 5 * 60 * 1000;

function generateUserCode(): string {
  const part1 = Math.random().toString(36).substring(2, 6).toUpperCase();
  const part2 = Math.random().toString(36).substring(2, 6).toUpperCase();

  return `${part1}-${part2}`;
}

export async function createDeviceChallenge() {
  const nonce = crypto.randomBytes(32).toString("hex");

  const challenge = await DeviceChallenge.create({
    nonce,
    status: "pending",
    expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
  });

  return challenge;
}

export async function startDeviceAuthorization(params: {
  certificate: DeviceCertificate;
  nonce: string;
  challengeSignature: string;
}) {
  const { certificate, nonce, challengeSignature } = params;

  const challenge = await DeviceChallenge.findOne({ nonce });

  if (!challenge) {
    throw new Error("Challenge not found");
  }

  if (challenge.status !== "pending") {
    throw new Error("Challenge already used or expired");
  }

  if (Date.now() > challenge.expiresAt.getTime()) {
    challenge.status = "expired";
    await challenge.save();
    throw new Error("Challenge expired");
  }

  const validManufacturerSignature = verifyManufacturerSignature(certificate);

  if (!validManufacturerSignature) {
    throw new Error("Invalid manufacturer certificate signature");
  }

  const validExpiration = verifyCertificateExpiration(certificate);

  if (!validExpiration) {
    throw new Error("Device certificate is expired or not yet valid");
  }

  const validDeviceSignature = verifyDeviceNonceSignature({
    nonce,
    signature: challengeSignature,
    devicePublicKey: certificate.devicePublicKey,
  });

  if (!validDeviceSignature) {
    throw new Error("Invalid device challenge signature");
  }

  challenge.status = "used";
  await challenge.save();

  const certificateFingerprint = getCertificateFingerprint(certificate);

  await Device.findOneAndUpdate(
    { deviceId: certificate.deviceId },
    {
      deviceId: certificate.deviceId,
      devicePublicKey: certificate.devicePublicKey,
      manufacturer: certificate.manufacturer,
      certificateFingerprint,
      status: "registered",
    },
    {
      upsert: true,
      new: true,
    }
  );

const deviceCode = crypto.randomUUID();
  const userCode = generateUserCode();

  const session = await DeviceAuthSession.create({
    deviceCode,
    userCode,
    deviceId: certificate.deviceId,
    status: "pending",
    expiresAt: new Date(Date.now() + DEVICE_AUTH_TTL_MS),
  });

  return {
    deviceCode: session.deviceCode,
    userCode: session.userCode,
    verificationUrl: `http://localhost:3000/activate?code=${session.userCode}`,
    expiresIn: 300,
    interval: 3,
  };
}

export async function approveDeviceAuthorization(userCode: string) {
  const session = await DeviceAuthSession.findOne({ userCode });

  if (!session) {
    throw new Error("Activation code not found");
  }

  if (Date.now() > session.expiresAt.getTime()) {
    session.status = "expired";
    await session.save();

    throw new Error("Activation code expired");
  }

  if (session.status === "approved") {
    return session;
  }

  session.status = "approved";
  session.approvedAt = new Date();

  await session.save();

  return session;
}

export async function pollDeviceAccessToken(deviceCode: string) {
  const session = await DeviceAuthSession.findOne({ deviceCode });

  if (!session) {
    return {
      status: "not_found",
    };
  }

  if (Date.now() > session.expiresAt.getTime()) {
    session.status = "expired";
    await session.save();

    return {
      status: "expired",
    };
  }

  if (session.status === "pending") {
    return {
      status: "pending",
    };
  }

  if (session.status === "approved") {
    const accessToken = createDeviceAccessToken(session.deviceId);

    return {
      status: "approved",
      accessToken,
    };
  }

  return {
    status: session.status,
  };
}