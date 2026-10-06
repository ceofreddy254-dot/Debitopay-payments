"use strict";

/*
 * Debito Pay mKesh STK-push backend.
 *
 * Required environment variables (set these in your host's Secrets/Environment
 * Variables settings; do not put the live API key in frontend code):
 *   DEBITOPAY_API_KEY
 *   DEBITOPAY_MERCHANT_ID
 *   DEBITOPAY_WALLET_CODE
 *
 * Required for a separately hosted frontend:
 *   FRONTEND_ORIGINS=https://your-static-site.example
 *     # comma-separated exact origins are allowed
 * Optional:
 *   PORT=3000
 *   DEBITOPAY_API_BASE_URL=https://gyqoaningqhurhvdugne.supabase.co/functions/v1
 *   POLL_INTERVAL_MS=5000
 *   POLL_TIMEOUT_MS=120000
 *   REQUEST_TIMEOUT_MS=15000
 *   RATE_LIMIT_MAX=30
 *   RATE_LIMIT_WINDOW_MS=60000
 *   TRUST_PROXY=false               # set true only behind a trusted proxy
 *
 * Frontend:
 *   POST /api/payments  { "amount": 100, "phone": "+258821234567" }
 *   (The frontend may use "number" instead of "phone".)
 *   Poll GET /api/payments/:receiptToken until receipt.status is terminal.
 *
 * Polling/receipts/idempotency are held in memory. A process restart clears
 * them; use a database for durable production records or multiple instances.
 */

const crypto = require("node:crypto");
const express = require("express");

const REQUIRED_ENV = [
  "DEBITOPAY_API_KEY",
  "DEBITOPAY_MERCHANT_ID",
  "DEBITOPAY_WALLET_CODE",
];

const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]?.trim());
if (missingEnv.length > 0) {
  console.error(
    `Missing required environment variables: ${missingEnv.join(", ")}`
  );
  process.exit(1);
}

const API_KEY = process.env.DEBITOPAY_API_KEY.trim();
const MERCHANT_ID = process.env.DEBITOPAY_MERCHANT_ID.trim();
const WALLET_CODE = process.env.DEBITOPAY_WALLET_CODE.trim();
const API_BASE_URL = (
  process.env.DEBITOPAY_API_BASE_URL ||
  "https://gyqoaningqhurhvdugne.supabase.co/functions/v1"
).replace(/\/+$/, "");
const ORCHESTRATOR_URL = `${API_BASE_URL}/payment-orchestrator`;
const PORT = parsePositiveInteger(process.env.PORT, 3000);
const POLL_INTERVAL_MS = parseBoundedInteger(
  process.env.POLL_INTERVAL_MS,
  5000,
  1000,
  60000
);
const POLL_TIMEOUT_MS = parseBoundedInteger(
  process.env.POLL_TIMEOUT_MS,
  120000,
  10000,
  900000
);
const REQUEST_TIMEOUT_MS = parseBoundedInteger(
  process.env.REQUEST_TIMEOUT_MS,
  15000,
  1000,
  120000
);
const RATE_LIMIT_MAX = parseBoundedInteger(
  process.env.RATE_LIMIT_MAX,
  30,
  1,
  10000
);
const RATE_LIMIT_WINDOW_MS = parseBoundedInteger(
  process.env.RATE_LIMIT_WINDOW_MS,
  60000,
  1000,
  3600000
);

if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(MERCHANT_ID)) {
  console.error("DEBITOPAY_MERCHANT_ID must be a UUID.");
  process.exit(1);
}
if (!/^\d{5}$/.test(WALLET_CODE)) {
  console.error("DEBITOPAY_WALLET_CODE must be the 5-digit wallet code.");
  process.exit(1);
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", process.env.TRUST_PROXY === "true" ? 1 : false);
app.use(express.json({ limit: "16kb", strict: true }));

const allowedOrigins = (process.env.FRONTEND_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.get("Origin");
  if (origin) {
    const wildcard = allowedOrigins.includes("*");
    if (!wildcard && !allowedOrigins.includes(origin)) {
      return res.status(403).json({
        success: false,
        error: "ORIGIN_NOT_ALLOWED",
        message: `The frontend origin "${origin}" is not in FRONTEND_ORIGINS.`,
      });
    }
    res.set("Access-Control-Allow-Origin", wildcard ? "*" : origin);
    res.set("Vary", "Origin");
    res.set(
      "Access-Control-Allow-Methods",
      "GET, POST, OPTIONS"
    );
    res.set(
      "Access-Control-Allow-Headers",
      "Content-Type, Idempotency-Key, X-Idempotency-Key"
    );
  }

  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

const rateLimits = new Map();
app.use("/api/payments", (req, res, next) => {
  const now = Date.now();
  if (rateLimits.size > 10000) {
    for (const [ip, value] of rateLimits) {
      if (now >= value.resetAt) rateLimits.delete(ip);
    }
    while (rateLimits.size > 15000) {
      rateLimits.delete(rateLimits.keys().next().value);
    }
  }
  const key = req.ip || req.socket.remoteAddress || "unknown";
  let entry = rateLimits.get(key);
  if (!entry || now >= entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    rateLimits.set(key, entry);
  }
  entry.count += 1;
  res.set("RateLimit-Limit", String(RATE_LIMIT_MAX));
  res.set("RateLimit-Remaining", String(Math.max(0, RATE_LIMIT_MAX - entry.count)));
  res.set("RateLimit-Reset", String(Math.ceil(entry.resetAt / 1000)));
  if (entry.count > RATE_LIMIT_MAX) {
    return res.status(429).json({
      success: false,
      error: "LOCAL_RATE_LIMIT_EXCEEDED",
      message: "Too many requests from this IP. Try again after the rate limit resets.",
    });
  }
  next();
});

const receipts = new Map();
const idempotencyRecords = new Map();
const RECEIPT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_STORED_RECORDS = 5000;
const TERMINAL_STATUSES = new Set(["success", "failed", "expired"]);

function parsePositiveInteger(value, fallback) {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseBoundedInteger(value, fallback, min, max) {
  const parsed = parsePositiveInteger(value, fallback);
  return Math.min(max, Math.max(min, parsed));
}

function isUuid(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
}

function validationError(message, code) {
  const error = new Error(message);
  error.code = code;
  error.httpStatus = 400;
  return error;
}

function validatePaymentBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw validationError("Request body must be a JSON object.", "INVALID_BODY");
  }

  const unknownFields = Object.keys(body).filter(
    (key) => key !== "amount" && key !== "phone" && key !== "number"
  );
  if (unknownFields.length > 0) {
    throw validationError(
      `Unsupported request field(s): ${unknownFields.join(", ")}.`,
      "UNKNOWN_FIELDS"
    );
  }

  let amountText;
  if (typeof body.amount === "number" && Number.isFinite(body.amount)) {
    amountText = String(body.amount);
  } else if (typeof body.amount === "string") {
    amountText = body.amount.trim();
  } else {
    throw validationError(
      "amount is required and must be a number with no more than 2 decimal places.",
      "INVALID_AMOUNT"
    );
  }

  if (!/^\d+(?:\.\d{1,2})?$/.test(amountText)) {
    throw validationError(
      "amount must be a positive MZN amount with no more than 2 decimal places.",
      "INVALID_AMOUNT"
    );
  }
  const amount = Number(amountText);
  if (!Number.isFinite(amount) || amount < 10) {
    throw validationError(
      "mKesh minimum transaction amount is 10 MZN.",
      "AMOUNT_BELOW_MINIMUM"
    );
  }

  if (body.phone !== undefined && body.number !== undefined) {
    throw validationError(
      "Send either phone or number, not both.",
      "DUPLICATE_PHONE_FIELDS"
    );
  }
  const suppliedPhone = body.phone ?? body.number;
  if (typeof suppliedPhone !== "string") {
    throw validationError("phone is required and must be a string.", "INVALID_PHONE");
  }
  const phoneInput = suppliedPhone.trim();
  // Debito Pay documents mKesh numbers as +258XXXXXXXXX, 258XXXXXXXXX,
  // or local 82XXXXXXX. Normalize the accepted forms to international format.
  if (!/^(?:\+?258)?82\d{7}$/.test(phoneInput)) {
    throw validationError(
      "Invalid mKesh phone number. Use +25882XXXXXXX, 25882XXXXXXX, or local 82XXXXXXX format.",
      "INVALID_PHONE"
    );
  }
  const digits = phoneInput.replace(/^\+/, "");
  const phone = digits.startsWith("258") ? `+${digits}` : `+258${digits}`;

  return { amount, phone };
}

function makeReceiptNumber() {
  const date = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  return `DP-${date}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
}

function sanitizeProviderValue(value) {
  if (typeof value === "string") return value.split(API_KEY).join("[REDACTED_API_KEY]");
  if (Array.isArray(value)) return value.map(sanitizeProviderValue);
  if (value && typeof value === "object") {
    const clean = {};
    for (const [key, child] of Object.entries(value)) {
      clean[key] = sanitizeProviderValue(child);
    }
    return clean;
  }
  return value;
}

function safeRecord(record) {
  const status = record.status;
  const isTerminalFailure = status === "failed" || status === "expired";
  return {
    success: status === "success" || status === "pending",
    status,
    receipt_token: record.token,
    receipt: {
      receipt_number: record.receiptNumber,
      source_id: record.sourceId,
      payment_id: record.paymentId || null,
      amount: record.amount,
      currency: "MZN",
      phone: record.phone,
      status,
      provider_reference: record.providerReference || null,
      created_at: record.createdAt,
      updated_at: record.updatedAt,
      confirmed_at: record.confirmedAt || null,
    },
    polling: {
      active: record.polling,
      last_checked_at: record.lastCheckedAt || null,
      timed_out: record.pollTimedOut,
    },
    ...(record.error
      ? {
          error: record.error.value,
          error_code: record.error.code || null,
          error_phase: record.error.phase,
          provider_http_status: record.error.providerHttpStatus || null,
          provider_response: record.error.providerResponse,
        }
      : {}),
    ...(record.providerResponse !== undefined
      ? { provider_response: record.providerResponse }
      : {}),
    ...(isTerminalFailure && !record.error
      ? {
          error:
            record.providerResponse?.error ??
            record.providerResponse?.message ??
            `Payment status is ${status}.`,
        }
      : {}),
  };
}

function setProviderResponse(record, result) {
  const body = result.body;
  record.providerResponse = sanitizeProviderValue(body);
  record.updatedAt = new Date().toISOString();
  const payment = body && typeof body === "object" ? body.payment : null;
  const paymentId =
    body?.payment_id || payment?.payment_id || payment?.id || record.paymentId;
  if (paymentId) record.paymentId = String(paymentId);
  const status = body?.status || payment?.status;
  if (typeof status === "string" && status.trim()) {
    record.status = status.trim().toLowerCase();
  }
  const providerReference =
    body?.provider_reference ||
    body?.providerReference ||
    body?.reference ||
    payment?.provider_reference ||
    payment?.reference;
  if (providerReference) record.providerReference = String(providerReference);
  if (record.status === "success" && !record.confirmedAt) {
    record.confirmedAt = new Date().toISOString();
  }
  record.error = null;
}

class DebitoPayError extends Error {
  constructor({ message, value, code, providerStatus, providerResponse, phase }) {
    super(message);
    this.name = "DebitoPayError";
    this.value = value;
    this.code = code;
    this.providerStatus = providerStatus;
    this.providerResponse = providerResponse;
    this.phase = phase;
    this.httpStatus =
      Number.isInteger(providerStatus) && providerStatus >= 400 && providerStatus <= 599
        ? providerStatus
        : 502;
  }
}

async function callDebitoPay(payload, { idempotencyKey, phase }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const headers = {
    Authorization: `Bearer ${API_KEY}`,
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (idempotencyKey) headers["X-Idempotency-Key"] = idempotencyKey;

  let response;
  let rawText;
  try {
    response = await fetch(ORCHESTRATOR_URL, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    rawText = await response.text();
  } catch (error) {
    const message =
      error?.name === "AbortError"
        ? `Debito Pay ${phase} request timed out after ${REQUEST_TIMEOUT_MS} ms.`
        : `Debito Pay ${phase} network request failed: ${error?.message || String(error)}`;
    throw new DebitoPayError({
      message,
      value: message,
      phase,
    });
  } finally {
    clearTimeout(timeout);
  }

  let body;
  try {
    body = rawText ? JSON.parse(rawText) : {};
  } catch {
    body = { raw: rawText };
  }

  if (!response.ok || body?.success === false) {
    const providerError =
      body && typeof body === "object"
        ? body.error ?? body.message ?? body.raw
        : undefined;
    const exactValue =
      providerError !== undefined
        ? sanitizeProviderValue(providerError)
        : sanitizeProviderValue(body);
    const displayMessage =
      typeof exactValue === "string"
        ? exactValue
        : JSON.stringify(exactValue);
    throw new DebitoPayError({
      message: displayMessage || `Debito Pay returned HTTP ${response.status}.`,
      value: exactValue,
      code: body?.error_code || body?.code || null,
      providerStatus: response.status,
      providerResponse: sanitizeProviderValue(body),
      phase,
    });
  }

  return { status: response.status, body };
}

function applyProviderError(record, error, phase) {
  // A failed create request means no payment was accepted. A failed status
  // check does not prove the customer payment failed, so keep its last status.
  if (phase === "create_payment") record.status = "failed";
  record.polling = false;
  record.updatedAt = new Date().toISOString();
  if (error instanceof DebitoPayError) {
    record.error = {
      value: error.value,
      code: error.code || null,
      providerHttpStatus: error.providerStatus || null,
      providerResponse: error.providerResponse,
      phase: error.phase || phase,
    };
  } else {
    const message = error?.message || String(error);
    record.error = {
      value: message,
      code: error?.code || null,
      providerHttpStatus: null,
      providerResponse: null,
      phase,
    };
  }
}

function updateFromStatusResult(record, result) {
  record.lastCheckedAt = new Date().toISOString();
  setProviderResponse(record, result);
}

async function pollUntilTerminal(record) {
  if (record.polling || !record.paymentId || TERMINAL_STATUSES.has(record.status)) return;
  record.polling = true;
  record.pollTimedOut = false;
  record.updatedAt = new Date().toISOString();
  const deadline = Date.now() + POLL_TIMEOUT_MS;

  try {
    while (!TERMINAL_STATUSES.has(record.status) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      if (Date.now() >= deadline) break;
      const result = await callDebitoPay(
        { action: "check-status", payment_id: record.paymentId },
        { phase: "poll_status" }
      );
      updateFromStatusResult(record, result);
    }
    if (!TERMINAL_STATUSES.has(record.status)) {
      record.pollTimedOut = true;
      record.updatedAt = new Date().toISOString();
    }
  } catch (error) {
    // Preserve the upstream response/error for the frontend instead of masking it.
    record.pollTimedOut = true;
    applyProviderError(record, error, "poll_status");
  } finally {
    record.polling = false;
    record.updatedAt = new Date().toISOString();
  }
}

function pruneStoredRecords() {
  const cutoff = Date.now() - RECEIPT_TTL_MS;
  for (const [token, record] of receipts) {
    if (record.createdAtMs < cutoff) {
      receipts.delete(token);
      if (record.idempotencyKey) idempotencyRecords.delete(record.idempotencyKey);
    }
  }
  while (receipts.size > MAX_STORED_RECORDS) {
    const oldestToken = receipts.keys().next().value;
    const oldest = receipts.get(oldestToken);
    receipts.delete(oldestToken);
    if (oldest?.idempotencyKey) {
      idempotencyRecords.delete(oldest.idempotencyKey);
    }
  }
}

function sendRecord(res, record) {
  const httpStatus =
    record.error?.providerHttpStatus ||
    (record.error ? 502 : record.status === "pending" ? 202 : 200);
  return res.status(httpStatus).json(safeRecord(record));
}

app.get("/health", (_req, res) => {
  res.json({ success: true, service: "debitopay-mkesh-backend" });
});

app.post("/api/payments", async (req, res) => {
  let validated;
  try {
    validated = validatePaymentBody(req.body);
  } catch (error) {
    return res.status(error.httpStatus || 400).json({
      success: false,
      error: error.code || "VALIDATION_ERROR",
      message: error.message,
    });
  }

  const idempotencyKey =
    req.get("Idempotency-Key") || req.get("X-Idempotency-Key") || crypto.randomUUID();
  if (!isUuid(idempotencyKey)) {
    return res.status(400).json({
      success: false,
      error: "INVALID_IDEMPOTENCY_KEY",
      message: "Idempotency-Key must be a UUID.",
    });
  }

  pruneStoredRecords();
  const fingerprint = JSON.stringify(validated);
  const existing = idempotencyRecords.get(idempotencyKey);
  if (existing) {
    if (existing.fingerprint !== fingerprint) {
      return res.status(409).json({
        success: false,
        error: "IDEMPOTENCY_KEY_REUSED",
        message: "This Idempotency-Key was already used with a different amount or phone number.",
      });
    }
    const previousRecord = receipts.get(existing.receiptToken);
    if (previousRecord) return sendRecord(res, previousRecord);
    idempotencyRecords.delete(idempotencyKey);
  }

  const receiptToken = crypto.randomBytes(32).toString("hex");
  const receiptNumber = makeReceiptNumber();
  const record = {
    token: receiptToken,
    receiptNumber,
    sourceId: receiptNumber,
    idempotencyKey,
    amount: validated.amount,
    phone: validated.phone,
    status: "pending",
    paymentId: null,
    providerReference: null,
    providerResponse: undefined,
    error: null,
    polling: false,
    pollTimedOut: false,
    lastCheckedAt: null,
    confirmedAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdAtMs: Date.now(),
  };
  receipts.set(receiptToken, record);
  idempotencyRecords.set(idempotencyKey, {
    fingerprint,
    receiptToken,
    createdAtMs: Date.now(),
  });

  try {
    const result = await callDebitoPay(
      {
        action: "process",
        payment_method: "mkesh",
        merchant_id: MERCHANT_ID,
        wallet_code: WALLET_CODE,
        amount: validated.amount,
        currency: "MZN",
        phone: validated.phone,
        source: "gateway",
        source_id: receiptNumber,
      },
      { idempotencyKey, phase: "create_payment" }
    );
    setProviderResponse(record, result);

    if (!record.paymentId) {
      const message =
        "Debito Pay accepted the request but did not return payment_id; status polling cannot continue.";
      record.status = "failed";
      record.error = {
        value: message,
        code: "MISSING_PAYMENT_ID",
        providerHttpStatus: result.status,
        providerResponse: record.providerResponse,
        phase: "create_payment",
      };
      return sendRecord(res, record);
    }

    if (!TERMINAL_STATUSES.has(record.status)) {
      // The API documents mKesh confirmation as asynchronous. Poll the
      // documented check-status action in the background while the frontend
      // reads this receipt endpoint.
      void pollUntilTerminal(record);
    }
    return sendRecord(res, record);
  } catch (error) {
    applyProviderError(record, error, "create_payment");
    return sendRecord(res, record);
  }
});

app.get("/api/payments/:receiptToken", (req, res) => {
  const { receiptToken } = req.params;
  if (!/^[0-9a-f]{64}$/i.test(receiptToken)) {
    return res.status(400).json({
      success: false,
      error: "INVALID_RECEIPT_TOKEN",
      message: "receiptToken must be the 64-character token returned when creating the payment.",
    });
  }

  const record = receipts.get(receiptToken);
  if (!record) {
    return res.status(404).json({
      success: false,
      error: "RECEIPT_NOT_FOUND",
      message: "Receipt was not found or has expired from this server's in-memory store.",
    });
  }

  if (
    record.paymentId &&
    !TERMINAL_STATUSES.has(record.status) &&
    !record.polling
  ) {
    void pollUntilTerminal(record);
  }
  return sendRecord(res, record);
});

// JSON parser errors and oversized requests are returned as explicit JSON.
app.use((error, _req, res, _next) => {
  if (res.headersSent) return;
  if (error?.type === "entity.parse.failed") {
    return res.status(400).json({
      success: false,
      error: "INVALID_JSON",
      message: error.message,
    });
  }
  if (error?.type === "entity.too.large") {
    return res.status(413).json({
      success: false,
      error: "REQUEST_TOO_LARGE",
      message: "JSON request body exceeds the 16 KB limit.",
    });
  }
  return res.status(500).json({
    success: false,
    error: "SERVER_ERROR",
    message: error?.message || "Unexpected server error.",
  });
});

app.listen(PORT, () => {
  console.log(`Debito Pay mKesh backend listening on port ${PORT}`);
  console.log(`Debito Pay endpoint: ${ORCHESTRATOR_URL}`);
  console.log("API credentials are loaded from environment variables and are not logged.");
});
