import jwt, { SignOptions } from "jsonwebtoken";

export interface DeviceAccessTokenPayload {
  sub: string;
  purpose: "anonymous_credential_issuance";
  deviceId: string;
}

export function createDeviceAccessToken(deviceId: string): string {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error("JWT_SECRET is not defined");
  }

  const payload: DeviceAccessTokenPayload = {
    sub: deviceId,
    deviceId,
    purpose: "anonymous_credential_issuance",
  };

  const options: SignOptions = {
    expiresIn: (process.env.JWT_EXPIRES_IN || "10m") as SignOptions["expiresIn"],
    issuer: "smart-health-watch-auth-server",
    audience: "smart-health-watch-anonymous-credential-server",
  };

  return jwt.sign(payload, secret, options);
}

export function verifyDeviceAccessToken(token: string): DeviceAccessTokenPayload {
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    throw new Error("JWT_SECRET is not defined");
  }

  const decoded = jwt.verify(token, secret, {
    issuer: "smart-health-watch-auth-server",
    audience: "smart-health-watch-anonymous-credential-server",
  }) as DeviceAccessTokenPayload;

  if (decoded.purpose !== "anonymous_credential_issuance") {
    throw new Error("Invalid token purpose");
  }

  return decoded;
}