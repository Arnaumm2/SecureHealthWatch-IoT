# Secure Health Watch IoT

Secure Health Watch IoT is a smart city prototype that simulates a privacy-preserving health monitoring system for wearable IoT devices.

The project is based on a smartwatch that sends sensitive health telemetry to a backend server. The main goal is to allow the system to verify that telemetry comes from an authorized device, while avoiding sending the real device identity in every telemetry message.

The system combines:

- Device authentication with manufacturer certificates
- User device authorization flow
- JWT-based temporary access tokens
- Blind signatures for anonymous credentials
- Anonymous telemetry verification
- CoAP communication through a CoAP-to-HTTP reverse proxy
- MongoDB for device sessions and anonymous credential registry

---

## Project idea

Wearable health devices can continuously monitor sensitive information such as heart rate, body temperature or risk indicators. This can be useful in smart city environments, especially for elderly people, patients with chronic diseases or emergency detection systems.

However, sending all telemetry directly linked to a real device identity creates a privacy problem.

This project proposes a solution where:

1. The smartwatch first proves that it is a legitimate device.
2. The user authorizes the device.
3. The device obtains a temporary JWT.
4. The JWT is used only to request a blind-signed anonymous credential.
5. The device sends telemetry using this anonymous credential instead of its real identity.
6. Telemetry is transported using CoAP, which is suitable for constrained IoT devices.

---

## Architecture

```txt
SecureHealthWatch-IoT/
├── manufacturer/
├── server/
├── device-client/
└── coap-http-reverseproxy/
