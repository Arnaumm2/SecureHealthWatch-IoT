import { Router } from "express";
import {
  verifyCredentialSignature,
  verifyCredentialFields,
  verifyTelemetrySignature,
} from "../services/anonymousCredentialVerify.service";

export const telemetryRouter = Router();

telemetryRouter.post("/telemetry", async (req, res) => {
  try {
    const {
      credential,
      credentialSignature,
      telemetry,
      telemetrySignature,
    } = req.body;

    if (!credential || !credentialSignature || !telemetry || !telemetrySignature) {
      return res.status(400).json({
        error: "credential, credentialSignature, telemetry and telemetrySignature are required",
      });
    }

    verifyCredentialFields(credential);

    const credentialValid = verifyCredentialSignature({
      credential,
      credentialSignature,
    });

    if (!credentialValid) {
      return res.status(401).json({
        error: "invalid_anonymous_credential_signature",
      });
    }

    const telemetryValid = verifyTelemetrySignature({
      telemetry,
      telemetrySignature,
      anonymousPublicKey: credential.anonymousPublicKey,
    });

    if (!telemetryValid) {
      return res.status(401).json({
        error: "invalid_telemetry_signature",
      });
    }

    console.log("\nValid anonymous telemetry received:");
    console.log(JSON.stringify(telemetry, null, 2));

    return res.json({
      status: "valid_anonymous_telemetry_received",
      receivedAt: new Date().toISOString(),
    });
  } catch (error: any) {
    return res.status(400).json({
      error: "telemetry_rejected",
      details: error.message,
    });
  }
});