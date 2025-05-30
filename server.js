require('dotenv').config();
const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const crypto = require("crypto");
const winston = require("winston");
const { GoogleGenerativeAI } = require("@google/generative-ai");

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_REQUESTS_PER_DAY = 50;

// Logger
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(info => `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`)
  ),
  transports: [new winston.transports.Console()]
});

// Env Checks
const ENC_KEY_RAW = process.env.ENCRYPTION_KEY || "";
const GOOGLE_API_KEY_RAW = process.env.GOOGLE_API_KEY || "";
const FIRST_USER_PASSWORD = process.env.FIRST_USER_PASSWORD || "";

if (!ENC_KEY_RAW || ENC_KEY_RAW.length > 32 || !GOOGLE_API_KEY_RAW || !FIRST_USER_PASSWORD) {
  logger.error("Invalid .env configuration");
  process.exit(1);
}

const ENC_KEY = Buffer.concat([Buffer.from(ENC_KEY_RAW), Buffer.alloc(32)], 32);

function encrypt(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  return iv.toString("hex") + cipher.update(text, "utf8", "hex") + cipher.final("hex");
}

function decrypt(encrypted, key) {
  const iv = Buffer.from(encrypted.slice(0, 32), "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  return decipher.update(encrypted.slice(32), "hex", "utf8") + decipher.final("utf8");
}

// API Key Encrypt/Decrypt (lightweight mode - in-memory use)
let API_KEY = GOOGLE_API_KEY_RAW;
const ai = new GoogleGenerativeAI(API_KEY);

// ✅ Allowed CORS Origins (updated)
const allowedOrigins = [
  "http://localhost:3000",
  "https://anand-vdgu.onrender.com",
  "https://htmlcssjsvirsion.tiiny.site",
  "https://chatlefy.tiiny.site",
  "https://anand-abc.netlify.app"  // ✅ Naya URL yahan add kiya gaya hai
];

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) cb(null, true);
    else cb(new Error("Not allowed by CORS"));
  }
}));

app.use(bodyParser.json());

// Load system instruction prompt
const SYSTEM_PROMPT_PATH = path.join(__dirname, "system.instruction.prompt");
let systemPromptText = "You are Anand, an AI assistant.";

try {
  if (fs.existsSync(SYSTEM_PROMPT_PATH)) {
    const data = fs.readFileSync(SYSTEM_PROMPT_PATH, "utf8").trim();
    if (data.length > 0) systemPromptText = data;
  }
} catch (e) {
  logger.warn("Failed to load system prompt, using default.");
}

// In-memory store
const userHistories = {};
const requestCounter = {};

function resetCountersDaily() {
  Object.keys(requestCounter).forEach(k => requestCounter[k] = 0);
  setTimeout(resetCountersDaily, 86400000);
}
resetCountersDaily();

app.post("/chat", async (req, res) => {
  const { userId, message } = req.body;

  if (!userId || !message) return res.status(400).json({ reply: "Invalid" });

  if (!userHistories[userId] && message !== FIRST_USER_PASSWORD)
    return res.status(403).json({ reply: "Unauthorized" });

  if (!userHistories[userId]) {
    const model = ai.getGenerativeModel({
      model: "gemini-2.5-flash-preview-05-20",
      generationConfig: { temperature: 0.9 },
      systemInstruction: { role: "system", parts: [{ text: systemPromptText }] }
    });
    const chat = model.startChat({ history: [] });
    userHistories[userId] = { chat };
    requestCounter[userId] = 0;
    return res.json({ reply: "Access granted" });
  }

  if (requestCounter[userId] >= MAX_REQUESTS_PER_DAY)
    return res.status(429).json({ reply: "Limit exceeded" });

  try {
    requestCounter[userId]++;
    const result = await userHistories[userId].chat.sendMessage(message);
    res.json({ reply: result.response.text() });
  } catch (err) {
    logger.error("AI error: " + err.message);
    res.status(500).json({ reply: "Unavailable" });
  }
});

app.listen(PORT, () => {
  logger.info(`Anand AI lightweight running on port ${PORT}`);
});
