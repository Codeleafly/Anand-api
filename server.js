// Load environment variables from .env file
require('dotenv').config();

const fs = require("fs"); // File system module for reading files
const path = require("path"); // Path module for handling file paths
const express = require("express"); // Express.js for creating the server
const bodyParser = require("body-parser"); // Middleware to parse JSON request bodies
const cors = require("cors"); // Middleware for enabling Cross-Origin Resource Sharing
const crypto = require("crypto"); // Crypto module for encryption (as per your original code)
const winston = require("winston"); // Winston for logging

// --- Official Google GenAI SDK Import (as per latest documentation) ---
const { GoogleGenAI } = require("@google/genai");

const app = express(); // Initialize Express app
const PORT = process.env.PORT || 3000; // Server port from .env or default to 3000
const MAX_REQUESTS_PER_DAY = 50; // Daily request limit per user

// --- Logger Setup ---
const logDir = path.join(__dirname, "logs");
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true }); // Ensure log directory exists
}

const logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(info => `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`)
    ),
    transports: [
        new winston.transports.File({
            filename: path.join(logDir, "error.log"),
            level: "error",
            format: winston.format.json() // JSON format for error logs
        }),
        new winston.transports.File({
            filename: path.join(logDir, "combined.log"),
            format: winston.format.json() // JSON format for combined logs
        }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(), // Colorize console output
                winston.format.printf(info => `[${info.timestamp}] ${info.level.toUpperCase()}: ${info.message}`)
            )
        }),
    ]
});

// --- Environment Variables Check and Loading ---
const ENC_KEY_RAW = process.env.ENCRYPTION_KEY || "";
const GOOGLE_API_KEY_RAW = process.env.GOOGLE_API_KEY || "";
const FIRST_USER_PASSWORD = process.env.FIRST_USER_PASSWORD || "";
// Fetch allowed origins from .env, split by comma, or default to an empty array
const ALLOWED_ORIGINS_ENV = process.env.ALLOWED_ORIGINS?.split(",").map(url => url.trim()) || [];

if (!ENC_KEY_RAW || ENC_KEY_RAW.length < 32 || !GOOGLE_API_KEY_RAW || !FIRST_USER_PASSWORD) {
    logger.error("Missing or invalid required .env configuration. Please ensure ENCRYPTION_KEY is at least 32 characters, and GOOGLE_API_KEY, FIRST_USER_PASSWORD are set.");
    process.exit(1); // Exit if critical environment variables are missing
}

// Ensure ENC_KEY is exactly 32 bytes for aes-256-cbc (key derivation)
const ENC_KEY = Buffer.concat([Buffer.from(ENC_KEY_RAW.slice(0, 32), 'utf8'), Buffer.alloc(32)], 32);

// --- Encryption/Decryption Functions (Provided by you - useful for other data) ---
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

// --- AI Setup: Initialize GoogleGenAI client with API Key ---
const ai = new GoogleGenAI({ apiKey: GOOGLE_API_KEY_RAW });

// --- CORS Setup ---
// Combined hardcoded and environment-variable allowed origins
const allowedOrigins = [
    "http://localhost:3000",
    "https://anand-vdgu.onrender.com",
    "https://htmlcssjsvirsion.tiiny.site",
    "https://chatlefy.tiiny.site",
    "https://anand-abc.netlify.app",
    ...ALLOWED_ORIGINS_ENV // Add origins from environment variable
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or same-origin requests)
        if (!origin) return callback(null, true); 
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            logger.warn(`CORS blocked request from origin: ${origin}`);
            callback(new Error(`Not allowed by CORS: ${origin}`)); // More descriptive error
        }
    }
}));

app.use(bodyParser.json()); // Enable JSON body parsing for Express

// --- Load System Instruction Prompt ---
const SYSTEM_PROMPT_PATH = path.join(__dirname, "system.instruction.prompt");
let systemPromptText = "You are Anand, an AI assistant. Your goal is to provide helpful and accurate information. You can use tools to assist users."; // Default system prompt

try {
    if (fs.existsSync(SYSTEM_PROMPT_PATH)) {
        const data = fs.readFileSync(SYSTEM_PROMPT_PATH, "utf8").trim();
        if (data.length > 0) {
            systemPromptText = data; // Use content if file exists and is not empty
            logger.info("System instruction prompt loaded from file.");
        } else {
            logger.warn("system.instruction.prompt file is empty, using default instruction.");
        }
    } else {
        logger.warn("system.instruction.prompt file not found, using default instruction.");
    }
} catch (e) {
    logger.error(`Failed to load system prompt from ${SYSTEM_PROMPT_PATH}, using default. Error: ${e.message}`);
}

// --- In-Memory Store for User Sessions and Rate Limiting ---
const userHistories = {}; // Stores chat sessions (Gemini's chat object)
const requestCounter = {}; // Stores daily request count for each user

// --- Daily Request Counter Reset Logic ---
function resetCountersDaily() {
    logger.info("Resetting daily request counters for all users.");
    Object.keys(requestCounter).forEach(k => requestCounter[k] = 0);
    // Schedule next reset after 24 hours (86400000 milliseconds)
    setTimeout(resetCountersDaily, 86400000);
}
resetCountersDaily(); // Initial call to start the daily reset cycle

// --- Chat API Endpoint ---
app.post("/chat", async (req, res) => {
    const { userId, message } = req.body; // Extract userId and message from request body

    // Input validation
    if (!userId || !message) {
        logger.warn("Received invalid chat request: Missing userId or message.");
        return res.status(400).json({ reply: "Invalid input. Please provide userId and message." });
    }

    const cleanedMessage = message.trim();
    const isFirstAccess = !userHistories[userId]; // Check if user has an existing session
    const isCorrectPassword = cleanedMessage === FIRST_USER_PASSWORD;

    // --- First Access & Authentication ---
    if (isFirstAccess) {
        if (!isCorrectPassword) {
            logger.warn(`Unauthorized access attempt by user: ${userId}. Incorrect password.`);
            return res.status(403).json({ reply: "Unauthorized access. Please provide the correct password to begin." });
        }
        
        // --- Initialize new chat session for authenticated user ---
        try {
            // **CORRECTED:** `ai.chats.create` direct call with model and config
            const chat = ai.chats.create({
                model: "gemini-2.5-flash", // Using gemini-2.5-flash as per official docs
                config: { // All generation and tool configurations go inside 'config'
                    systemInstruction: systemPromptText, // Use the loaded system prompt
                    temperature: 1.0, // A bit higher for more creative responses
                    topK: 1, // Top-k sampling
                    topP: 1, // Top-p sampling
                    thinkingConfig: { thinkingBudget: 0 }, // Disable thinking as per your request and official doc example
                    // --- Tools Integration as per Official Documentation ---
                    tools: [
                        { googleSearch: {} }, // Integrate Google Search tool
                        { codeExecution: {} }  // Integrate Code Execution tool
                    ],
                },
                history: [] // Start with an empty history for a new session
            });

            userHistories[userId] = { chat }; // Store the chat object for the user
            requestCounter[userId] = 0; // Initialize request counter for new user

            logger.info(`User ${userId} authenticated and new chat session started.`);
            return res.json({ reply: "Access granted. You can now start chatting with Anand." });

        } catch (initError) {
            logger.error(`Error initializing chat for user ${userId}: ${initError.message}`, initError);
            return res.status(500).json({ reply: "Anand AI is currently unavailable for new sessions. Please try again later." });
        }
    }

    // --- Rate Limit Check (for existing users) ---
    if (requestCounter[userId] >= MAX_REQUESTS_PER_DAY) {
        logger.warn(`User ${userId} exceeded daily request limit (${MAX_REQUESTS_PER_DAY} requests).`);
        return res.status(429).json({ reply: "Daily request limit exceeded. Please try again tomorrow." });
    }

    // --- Process Chat Message ---
    try {
        requestCounter[userId]++; // Increment request counter for this user

        // --- Real-time Date and Time Context ---
        const now = new Date();
        const dateTimeInfo = {
            currentDate: now.toLocaleDateString('en-CA'), // YYYY-MM-DD format (e.g., "2025-07-12")
            currentTime: now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }), // HH:MM:SS (24-hour format)
            timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone, // User's local timezone (e.g., "Asia/Kolkata")
            timestamp: now.toISOString(), // ISO 8601 format (e.g., "2025-07-12T16:33:34.000Z")
            currentYear: now.getFullYear(),
            currentDay: now.getDate(),
            currentMonth: now.getMonth() + 1 // Months are 0-indexed in JS (January is 0)
        };
        
        // Prepend date and time info to the message for model context
        // This sends a JSON string as part of the message to help the AI understand context.
        const messageForModel = `{"context": ${JSON.stringify(dateTimeInfo)}, "user_message": "${cleanedMessage}"}`;

        // Send message to the active chat session using the new SDK's object format
        const result = await userHistories[userId].chat.sendMessage({ message: messageForModel });

        // Extract the AI's reply text. The new SDK often returns `result.text` directly.
        const replyText = result.text || result.response.text(); // Fallback for robustness

        logger.info(`User ${userId} received reply: "${replyText.substring(0, 75)}${replyText.length > 75 ? '...' : ''}"`); // Log first 75 chars of reply
        res.json({ reply: replyText }); // Send AI's reply back to the client

    } catch (err) {
        logger.error(`AI chat error for user ${userId}: ${err.message}`, err); // Log full error object for debugging
        res.status(500).json({ reply: "Anand AI is currently unavailable due to an internal issue. Please try again in some time." });
    }
});

// --- Start Server ---
app.listen(PORT, () => {
    logger.info(`Anand AI running on http://localhost:${PORT}`);
    logger.info(`Allowed CORS origins: ${allowedOrigins.join(', ')}`);
});
