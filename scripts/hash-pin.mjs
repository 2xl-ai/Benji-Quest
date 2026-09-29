// Generates a PARENT_PIN_HASH or FAMILY_PASSCODE_HASH secret value.
// Usage: node scripts/hash-pin.mjs   (prompts without echoing what you type)
import { createInterface } from "node:readline";

const ITERATIONS = 100000; // Cloudflare Workers caps PBKDF2 at 100k iterations

// One interface for both prompts; output is muted so the PIN is never echoed.
const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: process.stdin.isTTY });
rl._writeToOutput = () => {};
const lines = rl[Symbol.asyncIterator]();
async function ask(question) {
  process.stdout.write(question);
  const { value = "" } = await lines.next();
  process.stdout.write("\n");
  return value;
}

const pin = await ask("New PIN / passcode: ");
const confirm = await ask("Confirm: ");
rl.close();
if (pin !== confirm) { console.error("They do not match."); process.exit(1); }
if (pin.length < 4) { console.error("Must be at least 4 characters."); process.exit(1); }
if (pin.length < 6) console.error("Warning: anything shorter than 6 characters is easy to guess. Consider a longer one.");

const salt = crypto.getRandomValues(new Uint8Array(16));
const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveBits"]);
const hash = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERATIONS }, key, 256));
const b64 = (u) => Buffer.from(u).toString("base64");

console.log(`\npbkdf2-sha256$${ITERATIONS}$${b64(salt)}$${b64(hash)}`);
