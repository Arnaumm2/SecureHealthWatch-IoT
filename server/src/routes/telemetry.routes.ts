import { Router } from "express";
import { AnonymousCredential } from "../models/AnonymousCredential.model";
import { verifyTelemetrySignature } from "../services/anonymousCredentialVerify.service";

export const telemetryRouter = Router();

telemetryRouter.post("/telemetry", async (req, res) => {
  try {
    console.log("\nRaw telemetry request received:");
    console.log(JSON.stringify(req.body, null, 2));

    const credentialId = req.body.credentialId || req.body.cid || req.body.c;
    const telemetry = req.body.telemetry || req.body.t;
    const telemetrySignature =
      req.body.telemetrySignature || req.body.sig || req.body.s;

    if (!credentialId || !telemetry || !telemetrySignature) {
      return res.status(400).json({
        error: "credentialId, telemetry and telemetrySignature are required",
      });
    }

    const credentialRecord = await AnonymousCredential.findOne({
      credentialId,
    });

    if (!credentialRecord) {
      return res.status(401).json({
        error: "anonymous_credential_not_registered",
      });
    }

    if (credentialRecord.status !== "active") {
      return res.status(401).json({
        error: "anonymous_credential_not_active",
      });
    }

    if (Date.now() > credentialRecord.expiresAt.getTime()) {
      credentialRecord.status = "expired";
      await credentialRecord.save();

      return res.status(401).json({
        error: "anonymous_credential_expired",
      });
    }

    const telemetryValid = verifyTelemetrySignature({
      telemetry,
      telemetrySignature,
      anonymousPublicKey: credentialRecord.anonymousPublicKey,
    });

    if (!telemetryValid) {
      return res.status(401).json({
        error: "invalid_telemetry_signature",
      });
    }

    console.log("\nValid anonymous telemetry received:");
    console.log("Credential ID:", credentialId);
    console.log(JSON.stringify(telemetry, null, 2));

    return res.json({
      status: "valid_anonymous_telemetry_received",
      credentialId,
      receivedAt: new Date().toISOString(),
    });
  } catch (error: any) {
    return res.status(400).json({
      error: "telemetry_rejected",
      details: error.message,
    });
  }
});
