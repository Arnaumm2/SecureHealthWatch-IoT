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
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Smart Health Watch Activation</title>

        <style>
          * {
            box-sizing: border-box;
          }

          body {
            margin: 0;
            min-height: 100vh;
            font-family: Arial, Helvetica, sans-serif;
            background: linear-gradient(135deg, #eaf4ff 0%, #f8fbff 50%, #ffffff 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #1f2937;
          }

          .card {
            width: 420px;
            background: white;
            border-radius: 24px;
            padding: 36px;
            box-shadow: 0 20px 45px rgba(15, 23, 42, 0.15);
            text-align: center;
            border: 1px solid #e5e7eb;
          }

          .watch-wrapper {
            display: flex;
            justify-content: center;
            margin-bottom: 24px;
          }

          .watch {
            width: 110px;
            height: 140px;
            position: relative;
          }

          .strap {
            width: 42px;
            height: 36px;
            background: #1e293b;
            margin: 0 auto;
            border-radius: 14px 14px 6px 6px;
          }

          .strap.bottom {
            border-radius: 6px 6px 14px 14px;
          }

          .screen {
            width: 100px;
            height: 90px;
            background: #0f172a;
            border-radius: 26px;
            margin: 4px auto;
            border: 4px solid #334155;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            box-shadow: inset 0 0 12px rgba(255,255,255,0.08);
          }

          .pulse {
            color: #ef4444;
            font-size: 32px;
            font-weight: bold;
            animation: pulse 1.2s infinite;
          }

          @keyframes pulse {
            0% { transform: scale(1); opacity: 0.8; }
            50% { transform: scale(1.15); opacity: 1; }
            100% { transform: scale(1); opacity: 0.8; }
          }

          h1 {
            margin: 0;
            font-size: 28px;
            color: #0f172a;
          }

          .subtitle {
            margin: 12px 0 26px;
            color: #64748b;
            font-size: 15px;
            line-height: 1.5;
          }

          .code-box {
            background: #f1f5f9;
            border: 1px dashed #94a3b8;
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 24px;
          }

          .code-label {
            font-size: 13px;
            color: #64748b;
            margin-bottom: 6px;
          }

          .code {
            font-size: 30px;
            font-weight: 800;
            letter-spacing: 2px;
            color: #b91c1c;
          }

          button {
            width: 100%;
            border: none;
            background: #0f172a;
            color: white;
            padding: 14px 20px;
            font-size: 16px;
            font-weight: 700;
            border-radius: 14px;
            cursor: pointer;
            transition: transform 0.15s ease, background 0.15s ease;
          }

          button:hover {
            background: #1e293b;
            transform: translateY(-1px);
          }

          .footer {
            margin-top: 18px;
            font-size: 12px;
            color: #94a3b8;
          }
        </style>
      </head>

      <body>
        <div class="card">
          <div class="watch-wrapper">
            <div class="watch">
              <div class="strap"></div>
              <div class="screen">
                <div class="pulse">♥</div>
              </div>
              <div class="strap bottom"></div>
            </div>
          </div>

          <h1>Smart Health Watch</h1>

          <p class="subtitle">
            A smartwatch is requesting permission to connect to your health monitoring account.
          </p>

          <div class="code-box">
            <div class="code-label">Activation code</div>
            <div class="code">${code}</div>
          </div>

          <form method="POST" action="/activate">
            <input type="hidden" name="code" value="${code}" />
            <button type="submit">Authorize device</button>
          </form>

          <div class="footer">
            Secure device authorization demo
          </div>
        </div>
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
