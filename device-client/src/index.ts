import axios from "axios";
import {
  loadDeviceCertificate,
  signNonceWithDevicePrivateKey,
} from "./deviceIdentity";

const AUTH_SERVER = "http://localhost:3000";

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

      console.log("\nNext step:");
      console.log("Use this JWT to request a blind signature.");
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