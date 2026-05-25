const coap = require("coap");

export function sendTelemetryOverCoap(payload: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = coap.request({
      hostname: "127.0.0.1",
      port: 5683,
      pathname: "/telemetry",
      method: "POST",
      options: {
        "Content-Format": "application/json",
      },
    });

    req.write(JSON.stringify(payload));

    req.on("response", (res: any) => {
      let body = "";

      res.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });

      res.on("end", () => {
        console.log("\nCoAP proxy response:");
        console.log(body);
        resolve();
      });
    });

    req.on("error", reject);

    req.end();
  });
}