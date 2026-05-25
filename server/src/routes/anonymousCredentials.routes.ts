import { Router } from "express";
import {
  getBlindIssuerPublicKey,
  blindSignMessage,
} from "../services/blindSignature.service";
import { verifyDeviceAccessToken } from "../services/token.service";

export const anonymousCredentialRouter = Router();

function extractBearerToken(authHeader: string | undefined): string {
  if (!authHeader) {
    throw new Error("Missing Authorization header");
  }

  const [type, token] = authHeader.split(" ");

  if (type !== "Bearer" || !token) {
    throw new Error("Invalid Authorization header");
  }

  return token;
}

anonymousCredentialRouter.get("/anonymous-credential/public-key", (_req, res) => {
  try {
    const publicKey = getBlindIssuerPublicKey();

    return res.json(publicKey);
  } catch (error: any) {
    return res.status(500).json({
      error: "failed_to_load_blind_issuer_public_key",
      details: error.message,
    });
  }
});

anonymousCredentialRouter.post("/anonymous-credential/blind-sign", (req, res) => {
  try {
    const token = extractBearerToken(req.headers.authorization);
    const decoded = verifyDeviceAccessToken(token);

    const { blindedMessage } = req.body;

    if (!blindedMessage) {
      return res.status(400).json({
        error: "blindedMessage is required",
      });
    }

    const blindSignature = blindSignMessage(blindedMessage);

    return res.json({
      blind_signature: blindSignature,
      signed_for: decoded.purpose,
    });
  } catch (error: any) {
    return res.status(401).json({
      error: "blind_signature_failed",
      details: error.message,
    });
  }
});