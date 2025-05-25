import "dotenv/config";
import express from "express";
import crypto from "crypto";
import crc32 from "buffer-crc32";
import fs from "fs/promises";
import fetch from "node-fetch";

const { LISTEN_PORT = 8888, LISTEN_PATH = "/webhook", CACHE_DIR = ".", WEBHOOK_ID } = process.env;

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
  const data = await response.text();
  await fs.writeFile(filePath, data);

  return data;
}

const app = express();

app.post(LISTEN_PATH, express.raw({ type: "application/json" }), async (request, response) => {
  const headers = request.headers;
  const event = request.body.toString(); // raw body as string
  const data = JSON.parse(event);

  console.log(`Headers:`, headers);
  console.log(`Parsed JSON:`, JSON.stringify(data, null, 2));

  const isValid = await verifySignature(event, headers);

  if (isValid) {
    console.log("Signature valid. Processing event...");
    // Process webhook data here
  } else {
    console.log("Invalid signature, rejecting event.");
  }

  response.sendStatus(200);
});

async function verifySignature(event, headers) {
  const transmissionId = headers["paypal-transmission-id"];
  const timeStamp = headers["paypal-transmission-time"];
  const crc = parseInt("0x" + crc32(Buffer.from(event)).toString("hex"));

  const message = `${transmissionId}|${timeStamp}|${WEBHOOK_ID}|${crc}`;
  console.log(`Signed message: ${message}`);

  const certPem = await downloadAndCache(headers["paypal-cert-url"]);

  const signatureBuffer = Buffer.from(headers["paypal-transmission-sig"], "base64");

  const verifier = crypto.createVerify("SHA256");
  verifier.update(message);

  return verifier.verify(certPem, signatureBuffer);
}

app.listen(LISTEN_PORT, () => {
  console.log(`Listening for PayPal webhooks on http://localhost:${LISTEN_PORT}${LISTEN_PATH}`);
});
