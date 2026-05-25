const coap = require("coap");

const agent = new coap.Agent({
  maxPacketSize: 4096,
});

export function sendTelemetryOverCoap(payload: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);

    console.log("\nCoAP payload size:");
    console.log(Buffer.byteLength(body, "utf8"), "bytes");

    const req = coap.request({
      hostname: "172.29.183.52",
      port: 5683,
      pathname: "/telemetry",
      method: "POST",
      agent,
      options: {
        "Content-Format": "application/json",
      },
    });

    const timeout = setTimeout(() => {
      reject(
        new Error(
          "CoAP request timed out. Check that the CoAP proxy is running on port 5683.",
        ),
      );
    }, 5000);

    req.write(body);

    req.on("response", (res: any) => {
      clearTimeout(timeout);

      let responseBody = "";

      res.on("data", (chunk: Buffer) => {
        responseBody += chunk.toString();
      });

      res.on("end", () => {
        console.log("\nCoAP proxy response:");
        console.log(responseBody);
        resolve();
      });
    });

    req.on("error", (error: Error) => {
      clearTimeout(timeout);
      reject(error);
    });

    req.end();
  });
}
