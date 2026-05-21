import { Router } from "express";
import {
  createDeviceChallenge,
  startDeviceAuthorization,
  approveDeviceAuthorization,
  pollDeviceAccessToken,
} from "../services/deviceAuth.service";

export const deviceAuthRouter = Router();

deviceAuthRouter.post("/device/challenge", async (_req, res) => {
  try {
    const challenge = await createDeviceChallenge();

    return res.json({
      nonce: challenge.nonce,
      expiresAt: challenge.expiresAt,
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "failed_to_create_challenge",
    });
  }
});

deviceAuthRouter.post("/device/start", async (req, res) => {
  try {
    const { certificate, nonce, challengeSignature } = req.body;

    if (!certificate || !nonce || !challengeSignature) {
      return res.status(400).json({
        error: "certificate, nonce and challengeSignature are required",
      });
    }

    const result = await startDeviceAuthorization({
      certificate,
      nonce,
      challengeSignature,
    });

    return res.json({
      device_code: result.deviceCode,
      user_code: result.userCode,
      verification_url: result.verificationUrl,
      expires_in: result.expiresIn,
      interval: result.interval,
    });
  } catch (error: any) {
    console.error(error.message);

    return res.status(400).json({
      error: "device_authorization_failed",
      details: error.message,
    });
  }
});

deviceAuthRouter.get("/activate", async (req, res) => {
  const code = req.query.code;

  if (!code || typeof code !== "string") {
    return res.status(400).send("Missing activation code");
  }

  return res.send(`
    <html>
      <body style="font-family: Arial; max-width: 600px; margin: 40px auto;">
        <h1>Smart Health Watch Activation</h1>
        <p>Activation code:</p>
        <h2>${code}</h2>

        <form method="POST" action="/activate">
          <input type="hidden" name="code" value="${code}" />
          <button type="submit" style="padding: 10px 20px;">
            Authorize device
          </button>
        </form>
      </body>
    </html>
  `);
});

deviceAuthRouter.post("/activate", async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).send("Missing activation code");
    }

    const session = await approveDeviceAuthorization(code);

    return res.send(`
      <html>
        <body style="font-family: Arial; max-width: 600px; margin: 40px auto;">
          <h1>Device authorized</h1>
          <p>The device <b>${session.deviceId}</b> has been authorized.</p>
          <p>You can now return to the smartwatch.</p>
        </body>
      </html>
    `);
  } catch (error: any) {
    return res.status(400).send(`
      <html>
        <body style="font-family: Arial; max-width: 600px; margin: 40px auto;">
          <h1>Activation failed</h1>
          <p>${error.message}</p>
        </body>
      </html>
    `);
  }
});

deviceAuthRouter.post("/device/token", async (req, res) => {
  try {
    const { device_code } = req.body;

    if (!device_code) {
      return res.status(400).json({
        error: "device_code is required",
      });
    }

    const result = await pollDeviceAccessToken(device_code);

    if (result.status === "pending") {
      return res.status(428).json({
        error: "authorization_pending",
      });
    }

    if (result.status === "expired") {
      return res.status(400).json({
        error: "expired_token",
      });
    }

    if (result.status === "not_found") {
      return res.status(404).json({
        error: "device_code_not_found",
      });
    }

    return res.json({
      access_token: result.accessToken,
      token_type: "Bearer",
      expires_in: 600,
      purpose: "anonymous_credential_issuance",
    });
  } catch (error: any) {
    return res.status(500).json({
      error: "token_generation_failed",
      details: error.message,
    });
  }
});