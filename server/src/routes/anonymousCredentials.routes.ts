import { Router } from "express";
import {
  getBlindIssuerPublicKey,
  blindSignMessage,
} from "../services/blindSignature.service";
import { verifyDeviceAccessToken } from "../services/token.service";
import { AnonymousCredential } from "../models/AnonymousCredential.model";
import {
  verifyCredentialSignature,
  verifyCredentialFields,
  getCredentialId,
} from "../services/anonymousCredentialVerify.service";

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

anonymousCredentialRouter.get(
  "/anonymous-credential/public-key",
  (_req, res) => {
    try {
      const publicKey = getBlindIssuerPublicKey();

      return res.json(publicKey);
    } catch (error: any) {
      return res.status(500).json({
        error: "failed_to_load_blind_issuer_public_key",
        details: error.message,
      });
    }
  },
);

anonymousCredentialRouter.post(
  "/anonymous-credential/blind-sign",
  (req, res) => {
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
  },
);

anonymousCredentialRouter.post(
  "/anonymous-credential/register",
  async (req, res) => {
    try {
      const { credential, credentialSignature } = req.body;

      if (!credential || !credentialSignature) {
        return res.status(400).json({
          error: "credential and credentialSignature are required",
        });
      }

      verifyCredentialFields(credential);

      const validSignature = verifyCredentialSignature({
        credential,
        credentialSignature,
      });

      if (!validSignature) {
        return res.status(401).json({
          error: "invalid_anonymous_credential_signature",
        });
      }

      const credentialId = getCredentialId(credential);

      await AnonymousCredential.findOneAndUpdate(
        { credentialId },
        {
          credentialId,
          anonymousPublicKey: credential.anonymousPublicKey,
          scope: credential.scope,
          issuedFor: credential.issuedFor,
          expiresAt: new Date(credential.expiresAt),
          status: "active",
        },
        {
          upsert: true,
          returnDocument: "after",
        },
      );

      return res.json({
        status: "anonymous_credential_registered",
        credentialId,
      });
    } catch (error: any) {
      return res.status(400).json({
        error: "anonymous_credential_registration_failed",
        details: error.message,
      });
    }
  },
);
