import express from "express";
import crypto from "crypto";
import crc32 from "buffer-crc32";
import fs from "fs/promises";
import fetch from "node-fetch";

const LISTEN_PORT = 8888;
const LISTEN_PATH = "/webhook";
const CACHE_DIR = ".";
const WEBHOOK_ID = "WH-54M31324A08453805-0TT498265C515724R"; // <-- Hardcoded webhook ID here

async function downloadAndCache(url, cacheKey) {
  if (!cacheKey) {
    cacheKey = url.replace(/\W+/g, "-");
  }
  const filePath = `${CACHE_DIR}/${cacheKey}`;

  // Check cache
  const cachedData = await fs.readFile(filePath, "utf-8").catch(() => null);
  if (cachedData) return cachedData;

  // Download cert
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch certificate: ${response.statusText}`);
  }
  const data = await response.text();
  await fs.writeFile(filePath, data);
  return data;
}

const app = express();

// Accept raw body (for signature verification)
app.use(LISTEN_PATH, express.raw({ type: "*/*" }));

app.post(LISTEN_PATH, async (request, response) => {
  const headers = request.headers;
  const contentType = headers["content-type"];
  const isJSON = contentType && contentType.includes("application/json");

  if (!isJSON) {
    return response.status(415).send("Unsupported Media Type");
  }

  const rawBody = request.body.toString("utf-8");

  let parsed;
  try {
    parsed = JSON.parse(rawBody);
  } catch (err) {
    console.error("Invalid JSON body");
    return response.status(400).send("Invalid JSON");
  }

  console.log(`Headers:`, headers);
  console.log(`Parsed JSON:`, JSON.stringify(parsed, null, 2));

  try {
    const isValid = await verifySignature(rawBody, headers);

    if (isValid) {
      console.log("✅ Signature valid. Processing event...");
      // TODO: Add your webhook event processing logic here

      return response.status(200).send("ok");
    } else {
      console.warn("❌ Invalid signature, rejecting event.");
      return response.status(400).send("Invalid signature");
    }
  } catch (error) {
    console.error("Error verifying signature:", error);
    return response.status(500).send("Internal Server Error");
  }
});

async function verifySignature(rawBody, headers) {
  const transmissionId = headers["paypal-transmission-id"];
  const timeStamp = headers["paypal-transmission-time"];
  const certUrl = headers["paypal-cert-url"];
  const transmissionSig = headers["paypal-transmission-sig"];

  if (!transmissionId || !timeStamp || !certUrl || !transmissionSig) {
    throw new Error("Missing PayPal headers required for signature verification");
  }

  const crc = crc32.unsigned(Buffer.from(rawBody));
  const message = `${transmissionId}|${timeStamp}|${WEBHOOK_ID}|${crc}`;
  console.log(`🔐 Signed message: ${message}`);

  const certPem = await downloadAndCache(certUrl);
  console.log(`🔑 Using cert from: ${certUrl}`);

  const signatureBuffer = Buffer.from(transmissionSig, "base64");

  const verifier = crypto.createVerify("SHA256");
  verifier.update(message);
  verifier.end();

  const isValid = verifier.verify(certPem, signatureBuffer);
  return isValid;
}

app.listen(LISTEN_PORT, () => {
  console.log(`🚀 Listening for PayPal webhooks on http://localhost:${LISTEN_PORT}${LISTEN_PATH}`);
});
