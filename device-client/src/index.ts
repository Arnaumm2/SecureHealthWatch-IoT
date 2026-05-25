import axios from "axios";
import {
  loadDeviceCertificate,
  signNonceWithDevicePrivateKey,
} from "./deviceIdentity";
import { buildAnonymousTelemetryPayload } from "./anonymousTelemetry";
import { sendTelemetryOverCoap } from "./coapTelemetry";
import {
  generateAnonymousKeyPair,
  createAnonymousCredential,
  blindCredential,
  unblindSignature,
  verifyUnblindedSignature,
} from "./blindSignature";

const AUTH_SERVER = "http://localhost:3000";

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function requestAnonymousCredential(accessToken: string) {
  console.log("\nRequesting blind issuer public key...");

  const publicKeyResponse = await axios.get(
    `${AUTH_SERVER}/anonymous-credential/public-key`
  );

  const issuerPublicKey = publicKeyResponse.data;

  console.log("Blind issuer public key received.");

  console.log("\nGenerating anonymous key pair...");

  const anonymousKeys = generateAnonymousKeyPair();

  console.log("Anonymous public key generated.");

  const credential = createAnonymousCredential(anonymousKeys.publicKey);

  console.log("\nCreating anonymous credential:");
  console.log({
    scope: credential.scope,
    issuedFor: credential.issuedFor,
    expiresAt: credential.expiresAt,
    nonce: credential.nonce,
  });

  console.log("\nBlinding credential...");

  const blinded = blindCredential(credential, issuerPublicKey);

  console.log("Blinded message:");
  console.log(blinded.blindedMessageHex);

  console.log("\nSending blinded credential to server...");

  const blindSignResponse = await axios.post(
    `${AUTH_SERVER}/anonymous-credential/blind-sign`,
    {
      blindedMessage: blinded.blindedMessageHex,
    },
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  const blindSignature = blindSignResponse.data.blind_signature;

  console.log("\nBlind signature received from server:");
  console.log(blindSignature);

  console.log("\nUnblinding signature...");

  const unblindedSignature = unblindSignature(
    blindSignature,
    blinded.blindingFactor,
    blinded.issuerN
  );

  console.log("Unblinded signature:");
  console.log(unblindedSignature);

  const valid = verifyUnblindedSignature({
    message: blinded.message,
    signatureHex: unblindedSignature,
    issuerN: blinded.issuerN,
    issuerE: blinded.issuerE,
  });

  console.log("\nAnonymous credential signature valid?");
  console.log(valid ? "YES" : "NO");

  if (!valid) {
    throw new Error("Invalid unblinded signature");
  }

  console.log("\nAnonymous credential ready!");
  console.log("From now on, telemetry should use:");
  console.log("- anonymous credential");
  console.log("- anonymous private key");
  console.log("- NOT the original device certificate");
  console.log("- NOT the JWT");
  return {
  credential,
  credentialSignature: unblindedSignature,
  anonymousPrivateKey: anonymousKeys.privateKey,
};
}

async function pollForAccessToken(deviceCode: string, intervalSeconds: number) {
  console.log("\nWaiting for user authorization...");

  while (true) {
    await sleep(intervalSeconds * 1000);

    try {
      const response = await axios.post(`${AUTH_SERVER}/device/token`, {
        device_code: deviceCode,
      });

      console.log("\nDevice authorized!");
      console.log("JWT access token received:");
      console.log(response.data.access_token);

      console.log("\nToken purpose:");
      console.log(response.data.purpose);

     console.log("\nUsing JWT to request anonymous credential...");

    const anonymousCredentialResult = await requestAnonymousCredential(
  response.data.access_token
);

console.log("\nBuilding anonymous telemetry payload...");

const telemetryPayload = buildAnonymousTelemetryPayload({
  credential: anonymousCredentialResult.credential,
  credentialSignature: anonymousCredentialResult.credentialSignature,
  anonymousPrivateKey: anonymousCredentialResult.anonymousPrivateKey,
});

console.log("\nSending telemetry over CoAP...");
await sendTelemetryOverCoap(telemetryPayload);

break;

    break;
    } catch (error: any) {
      const responseError = error.response?.data?.error;

      if (responseError === "authorization_pending") {
        console.log("Still waiting for user authorization...");
        continue;
      }

      console.error("Polling failed:");

      if (error.response?.data) {
        console.error(error.response.data);
      } else {
        console.error(error.message);
      }

      break;
    }
  }
}

async function main() {
  console.log("Smartwatch booting...");
  console.log("Loading device certificate...");

  const certificate = loadDeviceCertificate();

  console.log(`Device ID: ${certificate.deviceId}`);
  console.log(`Manufacturer: ${certificate.manufacturer}`);

  console.log("\nRequesting challenge from server...");

  const challengeResponse = await axios.post(
    `${AUTH_SERVER}/device/challenge`
  );

  const { nonce } = challengeResponse.data;

  console.log("Challenge received:");
  console.log(nonce);

  console.log("\nSigning challenge with device private key...");

  const challengeSignature = signNonceWithDevicePrivateKey(nonce);

  console.log("Sending certificate + signed challenge to server...");

  const startResponse = await axios.post(`${AUTH_SERVER}/device/start`, {
    certificate,
    nonce,
    challengeSignature,
  });

  const {
    verification_url,
    user_code,
    device_code,
    interval,
  } = startResponse.data;

  console.log("\nDevice accepted by server.");
  console.log("QR / activation simulation:");
  console.log(verification_url);

  console.log("\nUser code:");
  console.log(user_code);

  console.log("\nDevice code:");
  console.log(device_code);

  await pollForAccessToken(device_code, interval);
}

main().catch((error: any) => {
  console.error("Device client failed:");

  if (error.response?.data) {
    console.error(error.response.data);
  } else {
    console.error(error.message);
  }

  process.exit(1);
});