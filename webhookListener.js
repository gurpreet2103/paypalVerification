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

  let data;
  try {
    data = JSON.parse(event);
  } catch (err) {
    console.error("Invalid JSON body");
    return response.status(400).send("Invalid JSON");
  }

  console.log(`Headers:`, headers);
  console.log(`Parsed JSON:`, JSON.stringify(data, null, 2));

  try {
    const isValid = await verifySignature(event, headers);

    if (isValid) {
      console.log("Signature valid. Processing event...");
      // TODO: Add your webhook event processing logic here

      return response.status(200).send("ok");  // Success response
    } else {
      console.log("Invalid signature, rejecting event.");
      return response.status(400).send("Invalid signature"); // Signature failure response
    }
  } catch (error) {
    console.error("Error verifying signature:", error);
    return response.status(500).send("Internal Server Error");
  }
});

async function verifySignature(event, headers) {
  const transmissionId = headers["paypal-transmission-id"];
  const timeStamp = headers["paypal-transmission-time"];
  const certUrl = headers["paypal-cert-url"];
  const transmissionSig = headers["paypal-transmission-sig"];

  if (!transmissionId || !timeStamp || !certUrl || !transmissionSig) {
    throw new Error("Missing PayPal headers required for signature verification");
  }

  const crc = parseInt("0x" + crc32(Buffer.from(event)).toString("hex"));

  const message = `${transmissionId}|${timeStamp}|${WEBHOOK_ID}|${crc}`;
  console.log(`Signed message: ${message}`);

  const certPem = await downloadAndCache(certUrl);

  const signatureBuffer = Buffer.from(transmissionSig, "base64");

  const verifier = crypto.createVerify("SHA256");
  verifier.update(message);

  return verifier.verify(certPem, signatureBuffer);
}

app.listen(LISTEN_PORT, () => {
  console.log(`Listening for PayPal webhooks on http://localhost:${LISTEN_PORT}${LISTEN_PATH}`);
});
