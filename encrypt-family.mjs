import { webcrypto } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { stdin, stdout } from "node:process";

const ITERATIONS = 600_000;

function readHidden(prompt) {
  if (!stdin.isTTY) throw new Error("Run this script in a terminal to enter the password safely.");
  return new Promise((resolve, reject) => {
    stdout.write(prompt);
    stdin.setRawMode(true);
    stdin.setEncoding("utf8");
    stdin.resume();
    let value = "";

    const finish = () => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      stdout.write("\n");
    };
    const onData = chunk => {
      for (const character of chunk) {
        if (character === "\u0003") {
          finish();
          reject(new Error("Password entry cancelled."));
          return;
        }
        if (character === "\r" || character === "\n") {
          finish();
          resolve(value);
          return;
        }
        if (character === "\u007f" || character === "\b") value = value.slice(0, -1);
        else value += character;
      }
    };
    stdin.on("data", onData);
  });
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

const password = await readHidden("Password: ");
const confirmation = await readHidden("Confirm password: ");
if (!password || password !== confirmation) {
  throw new Error("Passwords must be non-empty and match.");
}

const plaintext = await readFile(new URL("./family.json", import.meta.url));
JSON.parse(plaintext);
const salt = webcrypto.getRandomValues(new Uint8Array(16));
const iv = webcrypto.getRandomValues(new Uint8Array(12));
const keyMaterial = await webcrypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(password),
  "PBKDF2",
  false,
  ["deriveKey"]
);
const key = await webcrypto.subtle.deriveKey(
  {
    name: "PBKDF2",
    salt,
    iterations: ITERATIONS,
    hash: "SHA-256"
  },
  keyMaterial,
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt"]
);
const ciphertext = await webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
const encryptedFamily = {
  version: 1,
  kdf: "PBKDF2-SHA-256",
  iterations: ITERATIONS,
  cipher: "AES-GCM",
  salt: toBase64(salt),
  iv: toBase64(iv),
  ciphertext: toBase64(ciphertext)
};

await writeFile(
  new URL("./family.enc.json", import.meta.url),
  `${JSON.stringify(encryptedFamily, null, 2)}\n`
);
console.log("Encrypted family data written to family.enc.json.");
