import dotenv from "dotenv";
import path from "path";
import express from "express";
import cors from "cors";

import { connectMongo } from "./config/mongo";
import { deviceAuthRouter } from "./routes/deviceAuth.routes";
import { anonymousCredentialRouter } from "./routes/anonymousCredentials.routes";
import { telemetryRouter } from "./routes/telemetry.routes";


const envPath = path.resolve(__dirname, "../.env");
const dotenvResult = dotenv.config({ path: envPath });

console.log("Loading .env from:", envPath);
console.log("dotenv parsed:", dotenvResult.parsed);
console.log("dotenv error:", dotenvResult.error);

async function bootstrap() {
  console.log("Current working directory:", process.cwd());
  console.log("MONGO_URI loaded:", process.env.MONGO_URI ? "yes" : "no");

  const app = express();

  app.use(cors());
  app.use(express.json({ limit: "2mb" }));
  app.use(express.urlencoded({ extended: true }));

  app.use(deviceAuthRouter);
  app.use(anonymousCredentialRouter);
  app.use(telemetryRouter);
  
  const port = process.env.PORT || 3000;

  await connectMongo();

  app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
  });
}

bootstrap().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});