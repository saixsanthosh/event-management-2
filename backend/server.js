const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const crypto = require("crypto");
const store = require("./store");

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";
const SECRET = "event_secret_key";
const APPROVAL_SEQUENCE = ["President", "Faculty", "HOD", "VP", "Dean"];
const LOGIN_MAX_ATTEMPTS = 3;
const LOGIN_LOCK_MINUTES = 15;
const RAZORPAY_KEY_ID = sanitizeEnv(process.env.RAZORPAY_KEY_ID, 120);
const RAZORPAY_KEY_SECRET = sanitizeEnv(process.env.RAZORPAY_KEY_SECRET, 180);
const RAZORPAY_CURRENCY = sanitizeEnv(process.env.RAZORPAY_CURRENCY, 10) || "INR";

const fs = require("fs");
const UPLOAD_DIR = path.join(__dirname, "uploads", "posters");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const UPI_DIR = path.join(__dirname, "uploads", "upi");
if (!fs.existsSync(UPI_DIR)) fs.mkdirSync(UPI_DIR, { recursive: true });

function sanitizeEnv(value, max) {
  return String(value || "").trim().slice(0, max || 200);
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const ext = (file.originalname.match(/\.(jpg|jpeg|png|gif|webp)$/i) || [null, "jpg"])[1];
      cb(null, `event-${req.params.id}-${Date.now()}.${ext}`);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /image\/(jpeg|jpg|png|gif|webp)/.test(file.mimetype);
    if (allowed) cb(null, true);
    else cb(new Error("Only images (jpeg, png, gif, webp) allowed"));
  }
});

const uploadUPI = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPI_DIR),
    filename: (req, file, cb) => {
      const ext = (file.originalname.match(/\.(jpg|jpeg|png|gif|webp)$/i) || [null, "png"])[1];
      cb(null, `upi-${Date.now()}.${ext}`);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /image\/(jpeg|jpg|png|gif|webp)/.test(file.mimetype);
    if (allowed) cb(null, true);
    else cb(new Error("Only images (jpeg, png, gif, webp) allowed"));
  }
});

app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

/* =========================
   AUTH MIDDLEWARE
========================= */
function verifyToken(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(403).json({ success: false, message: "No token" });

  const token = header.split(" ")[1];
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ success: false, message: "Invalid token" });
    req.user = decoded;
    next();
  });
}

/* =========================
   ROLE CHECK
========================= */
function allowRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: "Access denied" });
    }
    next();
  };
}

/* =========================
   BASIC SECURITY HELPERS
========================= */
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;
const rateBuckets = new Map();

function isRateLimited(key, limit) {
  const now = Date.now();
  const bucket = rateBuckets.get(key) || { count: 0, start: now };
  if (now - bucket.start > RATE_LIMIT_WINDOW_MS) {
    bucket.count = 0;
    bucket.start = now;
  }
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  return bucket.count > limit;
}

function rateLimit(limit) {
  return (req, res, next) => {
    const key = `${req.ip || "unknown"}:${req.path}`;
    if (isRateLimited(key, limit)) {
      return res.status(429).json({ success: false, message: "Too many requests, try again later" });
    }
    next();
  };
}

function sanitizeString(value, max = 200) {
  return String(value || "").trim().slice(0, max);
}

function isRazorpayConfigured() {
  return Boolean(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET);
}

function toMoneyPaise(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return 0;
  return Math.round(num * 100);
}

async function createRazorpayOrder(amountPaise, receipt, notes) {
  const basic = Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString("base64");
  const response = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: {
      "Authorization": `Basic ${basic}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      amount: amountPaise,
      currency: RAZORPAY_CURRENCY,
      receipt,
      payment_capture: 1,
      notes: notes || {}
    })
  });

  let payload = null;
  try {
    payload = await response.json();
  } catch (_) {
    payload = null;
  }
  if (!response.ok || !payload || !payload.id) {
    const message = payload && payload.error && payload.error.description
      ? payload.error.description
      : "Unable to create Razorpay order";
    throw new Error(message);
  }
  return payload;
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isValidPhone(value) {
  return /^[0-9+\-\s]{7,15}$/.test(value);
}

function isValidDate(value) {
  if (!value) return true;
  return !Number.isNaN(Date.parse(value));
}

function isStrongPassword(value) {
  const str = String(value || "");
  if (str.length < 8) return false;
  if (!/[A-Z]/.test(str)) return false;
  if (!/[0-9]/.test(str)) return false;
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(str)) return false;
  return true;
}

function generateUsername(role, subEventId, users) {
  const prefix = role === "Coordinator" ? "coord" : "vol";
  for (let i = 0; i < 10; i += 1) {
    const suffix = Math.floor(1000 + Math.random() * 9000);
    const candidate = `${prefix}-${subEventId}-${suffix}`;
    const exists = users.some(u => u.username === candidate);
    if (!exists) return candidate;
  }
  return null;
}

function generatePassword() {
  return crypto.randomBytes(5).toString("hex");
}

function toSafeInt(value, fallback = null) {
  const num = Number.parseInt(value, 10);
  return Number.isFinite(num) ? num : fallback;
}

function clampInt(value, min, max, fallback = 0) {
  const num = Number.parseInt(value, 10);
  if (!Number.isFinite(num)) return fallback;
  return Math.max(min, Math.min(max, num));
}

function normalizeParticipationType(value) {
  const normalized = sanitizeString(value, 20).toLowerCase();
  if (normalized === "team" || normalized === "teams") return "Team";
  return "Individual";
}

function normalizeTeamSizeRange(participationType, minValue, maxValue) {
  if (participationType !== "Team") {
    return { teamMinSize: 1, teamMaxSize: 1 };
  }
  const teamMinSize = clampInt(minValue, 2, 20, 2);
  const teamMaxSize = clampInt(maxValue, 2, 20, Math.max(4, teamMinSize));
  return {
    teamMinSize,
    teamMaxSize: Math.max(teamMinSize, teamMaxSize)
  };
}

function logAudit({ action, actor, role, details }) {
  const entry = {
    id: store.nextId("audit"),
    action,
    actor: actor || "System",
    role: role || "System",
    details: details || "",
    at: new Date().toISOString()
  };
  store.appendAuditLog(entry);
}

function ensureEventFields(event) {
  let changed = false;
  if (!event.approvalStatus) {
    event.approvalStatus = "Draft";
    changed = true;
  }
  if (!event.approvalStage) {
    event.approvalStage = "President";
    changed = true;
  }
  if (!Array.isArray(event.approvalHistory)) {
    event.approvalHistory = [];
    changed = true;
  }
  if (!event.results || typeof event.results !== "object") {
    event.results = {
      winner: "",
      runnerUp: "",
      thirdPlace: "",
      updatedAt: null,
      updatedBy: null
    };
    changed = true;
  } else {
    if (typeof event.results.winner !== "string") {
      event.results.winner = sanitizeString(event.results.winner, 120);
      changed = true;
    }
    if (typeof event.results.runnerUp !== "string") {
      event.results.runnerUp = sanitizeString(event.results.runnerUp, 120);
      changed = true;
    }
    if (typeof event.results.thirdPlace !== "string") {
      event.results.thirdPlace = sanitizeString(event.results.thirdPlace, 120);
      changed = true;
    }
    if (event.results.updatedAt !== null && typeof event.results.updatedAt !== "string") {
      event.results.updatedAt = null;
      changed = true;
    }
    if (event.results.updatedBy !== null && typeof event.results.updatedBy !== "string") {
      event.results.updatedBy = null;
      changed = true;
    }
  }
  return changed;
}

function ensureSubEventFields(subEvent) {
  let changed = false;
  if (subEvent.participationType !== "Individual" && subEvent.participationType !== "Team") {
    subEvent.participationType = normalizeParticipationType(subEvent.participationType);
    changed = true;
  }
  const normalizedTeam = normalizeTeamSizeRange(
    subEvent.participationType,
    subEvent.teamMinSize,
    subEvent.teamMaxSize
  );
  if (subEvent.teamMinSize !== normalizedTeam.teamMinSize) {
    subEvent.teamMinSize = normalizedTeam.teamMinSize;
    changed = true;
  }
  if (subEvent.teamMaxSize !== normalizedTeam.teamMaxSize) {
    subEvent.teamMaxSize = normalizedTeam.teamMaxSize;
    changed = true;
  }
  if (!subEvent.results || typeof subEvent.results !== "object") {
    subEvent.results = {
      winner: "",
      runnerUp: "",
      thirdPlace: "",
      participants: [],
      participantsUpdatedAt: null,
      participantsUpdatedBy: null,
      updatedAt: null,
      updatedBy: null
    };
    changed = true;
  } else {
    if (typeof subEvent.results.winner !== "string") {
      subEvent.results.winner = sanitizeString(subEvent.results.winner, 120);
      changed = true;
    }
    if (typeof subEvent.results.runnerUp !== "string") {
      subEvent.results.runnerUp = sanitizeString(subEvent.results.runnerUp, 120);
      changed = true;
    }
    if (typeof subEvent.results.thirdPlace !== "string") {
      subEvent.results.thirdPlace = sanitizeString(subEvent.results.thirdPlace, 120);
      changed = true;
    }
    if (!Array.isArray(subEvent.results.participants)) {
      subEvent.results.participants = [];
      changed = true;
    } else {
      const normalizedParticipants = subEvent.results.participants
        .filter(item => item && typeof item === "object")
        .map((item) => ({
          id: toSafeInt(item.id) || null,
          name: sanitizeString(item.name, 120),
          college: sanitizeString(item.college, 120),
          paymentStatus: sanitizeString(item.paymentStatus, 20),
          attendance: Boolean(item.attendance)
        }))
        .filter((item) => item.name);
      if (JSON.stringify(normalizedParticipants) !== JSON.stringify(subEvent.results.participants)) {
        subEvent.results.participants = normalizedParticipants;
        changed = true;
      }
    }
    if (subEvent.results.participantsUpdatedAt !== null && typeof subEvent.results.participantsUpdatedAt !== "string") {
      subEvent.results.participantsUpdatedAt = null;
      changed = true;
    }
    if (subEvent.results.participantsUpdatedBy !== null && typeof subEvent.results.participantsUpdatedBy !== "string") {
      subEvent.results.participantsUpdatedBy = null;
      changed = true;
    }
    if (subEvent.results.updatedAt !== null && typeof subEvent.results.updatedAt !== "string") {
      subEvent.results.updatedAt = null;
      changed = true;
    }
    if (subEvent.results.updatedBy !== null && typeof subEvent.results.updatedBy !== "string") {
      subEvent.results.updatedBy = null;
      changed = true;
    }
  }
  return changed;
}

function getNextApprovalStage(currentStage) {
  const idx = APPROVAL_SEQUENCE.indexOf(currentStage);
  if (idx === -1) return null;
  if (idx === APPROVAL_SEQUENCE.length - 1) return "Approved";
  return APPROVAL_SEQUENCE[idx + 1];
}

app.use(cors());

// Serve frontend static files (so /manage-subevents.html works on :3000)
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));
app.use(bodyParser.json({ limit: "200kb" }));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(express.static(path.join(__dirname, "..", "frontend")));

/* =========================
   LOGIN API
========================= */
app.post("/api/auth/login", rateLimit(20), async (req, res) => {
  const username = sanitizeString(req.body.username, 50);
  const password = String(req.body.password || "");
  if (!username || !password) {
    return res.json({ success: false, message: "Username and password required" });
  }
  const users = store.getUsers();
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.json({ success: false, message: "User not found" });
  }
  if (user.lockUntil && Date.now() < Date.parse(user.lockUntil)) {
    return res.json({ success: false, message: `Account locked. Try again after ${user.lockUntil}` });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
    if (user.failedLoginAttempts >= LOGIN_MAX_ATTEMPTS) {
      const lockUntil = new Date(Date.now() + LOGIN_LOCK_MINUTES * 60 * 1000).toISOString();
      user.lockUntil = lockUntil;
      user.failedLoginAttempts = 0;
    }
    store.saveUsers(users);
    return res.json({ success: false, message: "Wrong password" });
  }

  user.failedLoginAttempts = 0;
  user.lockUntil = null;
  store.saveUsers(users);

  const token = jwt.sign(
    { id: user.id, role: user.role },
    SECRET,
    { expiresIn: "2h" }
  );

  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    }
  });

  logAudit({
    action: "Login",
    actor: user.username,
    role: user.role,
    details: "User logged in"
  });
});

/* =========================
   CHANGE PASSWORD
========================= */
app.post("/api/auth/change-password", verifyToken, rateLimit(10), async (req, res) => {
  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");
  if (!currentPassword || !newPassword) {
    return res.json({ success: false, message: "Current and new password required" });
  }
  if (!isStrongPassword(newPassword)) {
    return res.json({
      success: false,
      message: "Password must be at least 8 chars, include 1 uppercase, 1 number, and 1 symbol"
    });
  }

  const users = store.getUsers();
  const user = users.find(u => u.id === req.user.id);
  if (!user) {
    return res.json({ success: false, message: "User not found" });
  }

  const match = await bcrypt.compare(currentPassword, user.password);
  if (!match) {
    return res.json({ success: false, message: "Current password is incorrect" });
  }

  user.password = await bcrypt.hash(newPassword, 10);
  store.saveUsers(users);
  logAudit({
    action: "Change Password",
    actor: user.username,
    role: user.role,
    details: "Password updated"
  });
  res.json({ success: true });
});

/* =========================
   CREATE EVENT (President)
========================= */
app.post("/api/events", rateLimit(60), verifyToken, allowRoles("President"), (req, res) => {
  const name = sanitizeString(req.body.name, 120);
  const description = sanitizeString(req.body.description, 500);
  const date = sanitizeString(req.body.date, 40);

  if (!name) {
    return res.json({ success: false, message: "Event name required" });
  }
  if (!isValidDate(date)) {
    return res.json({ success: false, message: "Invalid date" });
  }

  const events = store.getEvents();
  const newEvent = {
    id: store.nextId("events"),
    name,
    description: description || "",
    date: date || "",
    status: "Upcoming",
    posterPath: null,
    approvalStatus: "Draft",
    approvalStage: "President",
    approvalHistory: [],
    results: {
      winner: "",
      runnerUp: "",
      thirdPlace: "",
      updatedAt: null,
      updatedBy: null
    }
  };

  events.push(newEvent);
  store.saveEvents(events);
  logAudit({
    action: "Create Event",
    actor: req.user.id,
    role: req.user.role,
    details: `Event ${newEvent.id}: ${newEvent.name}`
  });
  res.json({ success: true, event: newEvent });
});

/* =========================
   GET ALL EVENTS
========================= */
app.get("/api/events", (req, res) => {
  const events = store.getEvents();
  let changed = false;
  events.forEach(e => {
    if (ensureEventFields(e)) changed = true;
  });
  if (changed) store.saveEvents(events);
  res.json(events);
});

/* =========================
   GET EVENT BY ID
========================= */
app.get("/api/events/:id", (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid event id" });
  const event = store.getEvents().find(e => e.id === id);
  if (!event) return res.status(404).json({ success: false, message: "Event not found" });
  if (ensureEventFields(event)) {
    const events = store.getEvents();
    const index = events.findIndex(e => e.id === id);
    if (index !== -1) {
      events[index] = event;
      store.saveEvents(events);
    }
  }
  res.json(event);
});

/* =========================
   UPDATE EVENT (President)
========================= */
app.put("/api/events/:id", rateLimit(60), verifyToken, allowRoles("President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid event id" });
  const name = req.body.name !== undefined ? sanitizeString(req.body.name, 120) : undefined;
  const description = req.body.description !== undefined ? sanitizeString(req.body.description, 500) : undefined;
  const date = req.body.date !== undefined ? sanitizeString(req.body.date, 40) : undefined;
  const status = req.body.status;
  const allowedStatus = ["Upcoming", "Ongoing", "Completed"];

  const events = store.getEvents();
  const event = events.find(e => e.id === id);
  if (!event) return res.status(404).json({ success: false, message: "Event not found" });
  ensureEventFields(event);

  if (name !== undefined) event.name = name;
  if (description !== undefined) event.description = description;
  if (date !== undefined) {
    if (!isValidDate(date)) return res.json({ success: false, message: "Invalid date" });
    event.date = date;
  }
  if (status !== undefined) {
    if (!allowedStatus.includes(status)) {
      return res.json({ success: false, message: "Invalid status" });
    }
    event.status = status;
  }

  store.saveEvents(events);
  logAudit({
    action: "Update Event",
    actor: req.user.id,
    role: req.user.role,
    details: `Event ${event.id}: ${event.name}`
  });
  res.json({ success: true, event });
});

/* =========================
   UPDATE EVENT RESULTS (Coordinator/President)
========================= */
app.put("/api/events/:id/results", rateLimit(60), verifyToken, allowRoles("Coordinator", "President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid event id" });

  const events = store.getEvents();
  const event = events.find(e => e.id === id);
  if (!event) return res.status(404).json({ success: false, message: "Event not found" });
  ensureEventFields(event);

  const status = sanitizeString(event.status, 20) || "Upcoming";
  if (status !== "Completed") {
    return res.json({
      success: false,
      message: "Results can be updated only after event status is Completed"
    });
  }

  const winner = sanitizeString(req.body.winner, 120);
  const runnerUp = sanitizeString(req.body.runnerUp, 120);
  const thirdPlace = sanitizeString(req.body.thirdPlace, 120);

  if (!winner && !runnerUp && !thirdPlace) {
    return res.json({ success: false, message: "Enter at least one result field" });
  }

  event.results = {
    winner,
    runnerUp,
    thirdPlace,
    updatedAt: new Date().toISOString(),
    updatedBy: `${req.user.role}#${req.user.id}`
  };

  store.saveEvents(events);
  logAudit({
    action: "Update Event Results",
    actor: req.user.id,
    role: req.user.role,
    details: `Event ${event.id}: ${event.name}`
  });

  res.json({ success: true, results: event.results, event });
});

/* =========================
   DELETE EVENT (President)
========================= */
app.delete("/api/events/:id", rateLimit(30), verifyToken, allowRoles("President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid event id" });

  const events = store.getEvents();
  const index = events.findIndex(e => e.id === id);
  if (index === -1) return res.status(404).json({ success: false, message: "Event not found" });

  events.splice(index, 1);
  store.saveEvents(events);

  // Cascade delete sub-events and related records
  const subEvents = store.getSubEvents();
  const subEventIds = subEvents.filter(se => se.eventId === id).map(se => se.id);
  if (subEventIds.length) {
    const remainingSubEvents = subEvents.filter(se => se.eventId !== id);
    store.saveSubEvents(remainingSubEvents);

    const registrations = store.getRegistrations();
    const remainingRegs = registrations.filter(r => !subEventIds.includes(r.subEventId));
    store.saveRegistrations(remainingRegs);

    const applications = store.getApplications();
    const remainingApps = applications.filter(a => !subEventIds.includes(a.subEventId));
    store.saveApplications(remainingApps);

    const users = store.getUsers();
    const remainingUsers = users.filter(u => {
      if (u.role !== "Coordinator" && u.role !== "Volunteer") return true;
      const sid = Number(u.subEventId);
      return !subEventIds.includes(sid);
    });
    store.saveUsers(remainingUsers);

    const removedRegIds = new Set(
      registrations.filter(r => subEventIds.includes(r.subEventId)).map(r => r.id)
    );
    if (removedRegIds.size) {
      const payments = store.getPayments();
      const remainingPayments = payments.filter(p => !removedRegIds.has(Number(p.registrationId)));
      store.savePayments(remainingPayments);
    }
  }

  logAudit({
    action: "Delete Event",
    actor: req.user.id,
    role: req.user.role,
    details: `Event ${id} deleted`
  });
  res.json({ success: true, message: "Event deleted" });
});

/* =========================
   SEND EVENT FOR APPROVAL (President)
========================= */
app.post("/api/events/:id/send-approval", rateLimit(20), verifyToken, allowRoles("President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid event id" });
  const events = store.getEvents();
  const event = events.find(e => e.id === id);
  if (!event) return res.status(404).json({ success: false, message: "Event not found" });

  ensureEventFields(event);

  if (event.approvalStatus === "Approved") {
    return res.json({ success: false, message: "Event already approved" });
  }

  if (event.approvalStatus === "Pending") {
    return res.json({ success: false, message: `Event is already with ${event.approvalStage}` });
  }

  // If it was sent back for revision, start a fresh approval cycle
  if (event.approvalStatus === "Revision Requested") {
    event.approvalHistory = [];
  }

  event.approvalStatus = "Pending";
  event.approvalStage = "Faculty";
  event.approvalHistory.push({
    action: "Sent",
    by: "President",
    at: new Date().toISOString()
  });

  store.saveEvents(events);
  logAudit({
    action: "Send Event For Approval",
    actor: req.user.id,
    role: req.user.role,
    details: `Event ${event.id}: ${event.name} -> Faculty`
  });
  res.json({ success: true, event });
});

/* =========================
   GET EVENTS PENDING FOR ROLE
========================= */
app.get("/api/events/approvals", verifyToken, allowRoles("Dean", "VP", "HOD", "Faculty", "President"), (req, res) => {
  const role = req.user.role;
  const events = store.getEvents();
  let changed = false;
  events.forEach(e => {
    if (ensureEventFields(e)) changed = true;
  });
  if (changed) store.saveEvents(events);

  const pending = events.filter(e => e.approvalStatus === "Pending" && e.approvalStage === role);
  res.json(pending);
});

/* =========================
   APPROVE / REJECT EVENT
========================= */
app.post("/api/events/:id/decision", rateLimit(30), verifyToken, allowRoles("Dean", "VP", "HOD", "Faculty", "President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid event id" });
  const action = sanitizeString(req.body.action, 20);
  const note = sanitizeString(req.body.note, 200);
  const role = req.user.role;

  if (!action || !["Approved", "Rejected"].includes(action)) {
    return res.json({ success: false, message: "Invalid action" });
  }

  const events = store.getEvents();
  const event = events.find(e => e.id === id);
  if (!event) return res.status(404).json({ success: false, message: "Event not found" });

  ensureEventFields(event);

  if (event.approvalStage !== role || event.approvalStatus !== "Pending") {
    return res.status(403).json({ success: false, message: "Not authorized for this event stage" });
  }

  if (action === "Approved") {
    const nextStage = getNextApprovalStage(role);
    if (nextStage === "Approved") {
      event.approvalStatus = "Approved";
      event.approvalStage = "Approved";
    } else {
      event.approvalStatus = "Pending";
      event.approvalStage = nextStage;
    }
  } else {
    event.approvalStatus = "Revision Requested";
    event.approvalStage = "President";
  }

  event.approvalHistory.push({
    action,
    by: role,
    note: note || "",
    at: new Date().toISOString()
  });

  store.saveEvents(events);
  logAudit({
    action: "Event Decision",
    actor: req.user.id,
    role: req.user.role,
    details: `Event ${event.id}: ${event.name} -> ${event.approvalStatus} @ ${event.approvalStage}`
  });
  res.json({ success: true, event });
});

/* =========================
   UPLOAD EVENT POSTER (President)
========================= */
app.post("/api/events/:id/poster", rateLimit(30), verifyToken, allowRoles("President"), (req, res, next) => {
  upload.single("poster")(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message || "Upload failed" });
    if (!req.file) return res.status(400).json({ success: false, message: "No file" });

    const id = toSafeInt(req.params.id);
    if (!id) return res.status(400).json({ success: false, message: "Invalid event id" });
    const events = store.getEvents();
    const event = events.find(e => e.id === id);
    if (!event) return res.status(404).json({ success: false, message: "Event not found" });

    const posterPath = "/uploads/posters/" + path.basename(req.file.path);
    event.posterPath = posterPath;
    store.saveEvents(events);
    logAudit({
      action: "Upload Event Poster",
      actor: req.user.id,
      role: req.user.role,
      details: `Event ${event.id}: ${event.name}`
    });
    res.json({ success: true, posterPath, event });
  });
});

/* =========================
   CREATE SUB-EVENT
========================= */
app.post("/api/subevents", rateLimit(60), verifyToken, allowRoles("President"), (req, res) => {
  const eventId = toSafeInt(req.body.eventId);
  const name = sanitizeString(req.body.name, 120);
  const coordinatorLimit = clampInt(req.body.coordinatorLimit, 0, 999, 0);
  const volunteerLimit = clampInt(req.body.volunteerLimit, 0, 999, 0);
  const fee = clampInt(req.body.fee, 0, 1000000, 0);
  const date = sanitizeString(req.body.date, 40);
  const time = sanitizeString(req.body.time, 20);
  const venue = sanitizeString(req.body.venue, 120);
  const participationType = normalizeParticipationType(req.body.participationType);
  const teamSizeRange = normalizeTeamSizeRange(
    participationType,
    req.body.teamMinSize,
    req.body.teamMaxSize
  );

  if (!eventId || !name) {
    return res.json({ success: false, message: "Missing fields" });
  }
  if (!isValidDate(date)) {
    return res.json({ success: false, message: "Invalid date" });
  }
  const eventExists = store.getEvents().some(e => e.id === eventId);
  if (!eventExists) {
    return res.status(404).json({ success: false, message: "Event not found" });
  }

  const subEvents = store.getSubEvents();
  const newSubEvent = {
    id: store.nextId("subevents"),
    eventId,
    name,
    coordinatorLimit,
    volunteerLimit,
    fee,
    date: date || "",
    time: time || "",
    venue: venue || "",
    participationType,
    teamMinSize: teamSizeRange.teamMinSize,
    teamMaxSize: teamSizeRange.teamMaxSize,
    results: {
      winner: "",
      runnerUp: "",
      thirdPlace: "",
      updatedAt: null,
      updatedBy: null
    }
  };

  subEvents.push(newSubEvent);
  store.saveSubEvents(subEvents);
  logAudit({
    action: "Create Sub-Event",
    actor: req.user.id,
    role: req.user.role,
    details: `Sub-event ${newSubEvent.id}: ${newSubEvent.name} (Event ${newSubEvent.eventId})`
  });
  res.json({ success: true, subEvent: newSubEvent });
});

/* =========================
   GET SUB-EVENTS BY EVENT
========================= */
app.get("/api/subevents/:eventId", (req, res) => {
  const eventId = toSafeInt(req.params.eventId);
  if (!eventId) return res.status(400).json({ success: false, message: "Invalid event id" });
  const subEvents = store.getSubEvents();
  let changed = false;
  subEvents.forEach(se => {
    if (ensureSubEventFields(se)) changed = true;
  });
  if (changed) store.saveSubEvents(subEvents);
  const list = subEvents.filter(se => se.eventId === eventId);
  res.json(list);
});

/* =========================
   GET SUB-EVENT BY ID
========================= */
app.get("/api/subevents/detail/:id", (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid sub-event id" });
  const subEvents = store.getSubEvents();
  const subEvent = subEvents.find(se => se.id === id);
  if (!subEvent) return res.status(404).json({ success: false, message: "Sub-event not found" });
  if (ensureSubEventFields(subEvent)) {
    store.saveSubEvents(subEvents);
  }
  res.json(subEvent);
});

/* =========================
   UPDATE SUB-EVENT (President)
========================= */
app.put("/api/subevents/:id", rateLimit(60), verifyToken, allowRoles("President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid sub-event id" });
  const name = req.body.name !== undefined ? sanitizeString(req.body.name, 120) : undefined;
  const coordinatorLimit = req.body.coordinatorLimit !== undefined
    ? clampInt(req.body.coordinatorLimit, 0, 999, 0)
    : undefined;
  const volunteerLimit = req.body.volunteerLimit !== undefined
    ? clampInt(req.body.volunteerLimit, 0, 999, 0)
    : undefined;
  const fee = req.body.fee !== undefined
    ? clampInt(req.body.fee, 0, 1000000, 0)
    : undefined;
  const date = req.body.date !== undefined ? sanitizeString(req.body.date, 40) : undefined;
  const time = req.body.time !== undefined ? sanitizeString(req.body.time, 20) : undefined;
  const venue = req.body.venue !== undefined ? sanitizeString(req.body.venue, 120) : undefined;
  const participationType = req.body.participationType !== undefined
    ? normalizeParticipationType(req.body.participationType)
    : undefined;
  const teamMinSize = req.body.teamMinSize !== undefined
    ? clampInt(req.body.teamMinSize, 2, 20, 2)
    : undefined;
  const teamMaxSize = req.body.teamMaxSize !== undefined
    ? clampInt(req.body.teamMaxSize, 2, 20, 4)
    : undefined;

  const subEvents = store.getSubEvents();
  const subEvent = subEvents.find(se => se.id === id);
  if (!subEvent) return res.status(404).json({ success: false, message: "Sub-event not found" });
  ensureSubEventFields(subEvent);

  if (name !== undefined) subEvent.name = name;
  if (coordinatorLimit !== undefined) subEvent.coordinatorLimit = Number(coordinatorLimit);
  if (volunteerLimit !== undefined) subEvent.volunteerLimit = Number(volunteerLimit);
  if (fee !== undefined) subEvent.fee = Number(fee);
  if (date !== undefined) {
    if (!isValidDate(date)) return res.json({ success: false, message: "Invalid date" });
    subEvent.date = date;
  }
  if (time !== undefined) subEvent.time = time;
  if (venue !== undefined) subEvent.venue = venue;
  if (participationType !== undefined) {
    subEvent.participationType = participationType;
  }
  if (subEvent.participationType === "Team") {
    if (teamMinSize !== undefined) subEvent.teamMinSize = teamMinSize;
    if (teamMaxSize !== undefined) subEvent.teamMaxSize = teamMaxSize;
    if (subEvent.teamMaxSize < subEvent.teamMinSize) {
      return res.json({ success: false, message: "Team max size must be greater than or equal to min size" });
    }
  } else {
    subEvent.teamMinSize = 1;
    subEvent.teamMaxSize = 1;
  }

  store.saveSubEvents(subEvents);
  logAudit({
    action: "Update Sub-Event",
    actor: req.user.id,
    role: req.user.role,
    details: `Sub-event ${subEvent.id}: ${subEvent.name}`
  });
  res.json({ success: true, subEvent });
});

/* =========================
   UPDATE SUB-EVENT RESULTS (Coordinator/President)
========================= */
app.put("/api/subevents/:id/results", rateLimit(60), verifyToken, allowRoles("Coordinator", "President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid sub-event id" });

  const subEvents = store.getSubEvents();
  const subEvent = subEvents.find(se => se.id === id);
  if (!subEvent) return res.status(404).json({ success: false, message: "Sub-event not found" });
  ensureSubEventFields(subEvent);

  const event = store.getEvents().find(e => e.id === subEvent.eventId);
  if (!event) return res.status(404).json({ success: false, message: "Parent event not found" });
  ensureEventFields(event);

  const status = sanitizeString(event.status, 20) || "Upcoming";
  if (status !== "Completed") {
    return res.json({
      success: false,
      message: "Results can be updated only after event status is Completed"
    });
  }

  const winner = sanitizeString(req.body.winner, 120);
  const runnerUp = sanitizeString(req.body.runnerUp, 120);
  const thirdPlace = sanitizeString(req.body.thirdPlace, 120);

  if (!winner && !runnerUp && !thirdPlace) {
    return res.json({ success: false, message: "Enter at least one result field" });
  }

  const existingParticipants = Array.isArray(subEvent.results.participants) ? subEvent.results.participants : [];
  const participantsUpdatedAt = typeof subEvent.results.participantsUpdatedAt === "string"
    ? subEvent.results.participantsUpdatedAt
    : null;
  const participantsUpdatedBy = typeof subEvent.results.participantsUpdatedBy === "string"
    ? subEvent.results.participantsUpdatedBy
    : null;

  subEvent.results = {
    winner,
    runnerUp,
    thirdPlace,
    participants: existingParticipants,
    participantsUpdatedAt,
    participantsUpdatedBy,
    updatedAt: new Date().toISOString(),
    updatedBy: `${req.user.role}#${req.user.id}`
  };

  store.saveSubEvents(subEvents);
  logAudit({
    action: "Update Sub-Event Results",
    actor: req.user.id,
    role: req.user.role,
    details: `Sub-event ${subEvent.id}: ${subEvent.name} (Event ${event.id}: ${event.name})`
  });

  res.json({ success: true, results: subEvent.results, subEvent, event });
});

/* =========================
   PUBLISH ATTENDED PARTICIPANTS TO RESULT LIST (Coordinator/President)
========================= */
app.put("/api/subevents/:id/participants", rateLimit(60), verifyToken, allowRoles("Coordinator", "President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid sub-event id" });

  const subEvents = store.getSubEvents();
  const subEvent = subEvents.find((se) => se.id === id);
  if (!subEvent) return res.status(404).json({ success: false, message: "Sub-event not found" });
  ensureSubEventFields(subEvent);

  const attended = store.getRegistrations()
    .filter((reg) => reg.subEventId === id && reg.attendance)
    .map((reg) => ({
      id: reg.id,
      name: sanitizeString(reg.name, 120),
      college: sanitizeString(reg.college, 120),
      paymentStatus: sanitizeString(reg.paymentStatus, 20),
      attendance: true
    }))
    .filter((participant) => participant.name);

  if (attended.length === 0) {
    return res.json({ success: false, message: "No attended participants found to submit" });
  }

  subEvent.results = {
    winner: sanitizeString(subEvent.results.winner, 120),
    runnerUp: sanitizeString(subEvent.results.runnerUp, 120),
    thirdPlace: sanitizeString(subEvent.results.thirdPlace, 120),
    participants: attended,
    participantsUpdatedAt: new Date().toISOString(),
    participantsUpdatedBy: `${req.user.role}#${req.user.id}`,
    updatedAt: subEvent.results.updatedAt || null,
    updatedBy: subEvent.results.updatedBy || null
  };

  store.saveSubEvents(subEvents);
  logAudit({
    action: "Publish Sub-Event Participants",
    actor: req.user.id,
    role: req.user.role,
    details: `Sub-event ${subEvent.id} published participants count ${attended.length}`
  });
  res.json({ success: true, count: attended.length, subEvent });
});

/* =========================
   DELETE SUB-EVENT (President)
========================= */
app.delete("/api/subevents/:id", rateLimit(30), verifyToken, allowRoles("President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid sub-event id" });

  const subEvents = store.getSubEvents();
  const index = subEvents.findIndex(se => se.id === id);
  if (index === -1) return res.status(404).json({ success: false, message: "Sub-event not found" });

  subEvents.splice(index, 1);
  store.saveSubEvents(subEvents);
  logAudit({
    action: "Delete Sub-Event",
    actor: req.user.id,
    role: req.user.role,
    details: `Sub-event ${id} deleted`
  });
  res.json({ success: true, message: "Sub-event deleted" });
});

/* =========================
   REGISTER STUDENT
========================= */
app.post("/api/register", rateLimit(40), (req, res) => {
  const subEventId = toSafeInt(req.body.subEventId);
  const transactionId = sanitizeString(req.body.transactionId, 80);
  const teamName = sanitizeString(req.body.teamName, 120);
  const membersInput = Array.isArray(req.body.members) ? req.body.members : null;

  if (!subEventId) {
    return res.json({ success: false, message: "Sub-event is required" });
  }
  const subEvents = store.getSubEvents();
  const subEvent = subEvents.find(se => se.id === subEventId);
  if (!subEvent) {
    return res.status(404).json({ success: false, message: "Sub-event not found" });
  }
  let subEventChanged = false;
  if (ensureSubEventFields(subEvent)) {
    subEventChanged = true;
  }
  if (subEventChanged) {
    store.saveSubEvents(subEvents);
  }

  const registrations = store.getRegistrations();
  if (subEvent.participationType === "Team") {
    if (!membersInput || membersInput.length === 0) {
      return res.json({ success: false, message: "Team member details are required" });
    }
    const teamMinSize = Number(subEvent.teamMinSize || 2);
    const teamMaxSize = Number(subEvent.teamMaxSize || 4);
    if (membersInput.length < teamMinSize || membersInput.length > teamMaxSize) {
      return res.json({ success: false, message: `Team size must be between ${teamMinSize} and ${teamMaxSize}` });
    }

    const normalizedMembers = membersInput.map((member, index) => ({
      name: sanitizeString(member && member.name, 120),
      college: sanitizeString(member && member.college, 120),
      department: sanitizeString(member && member.department, 120),
      email: sanitizeString(member && member.email, 120),
      mobile: sanitizeString(member && member.mobile, 20),
      memberIndex: index + 1
    }));

    for (const member of normalizedMembers) {
      if (!member.name || !member.college || !member.email || !member.mobile) {
        return res.json({ success: false, message: "All team member fields are required" });
      }
      if (!isValidEmail(member.email)) {
        return res.json({ success: false, message: `Invalid email for ${member.name}` });
      }
      if (!isValidPhone(member.mobile)) {
        return res.json({ success: false, message: `Invalid mobile number for ${member.name}` });
      }
    }

    const uniqueEmails = new Set(normalizedMembers.map((member) => member.email.toLowerCase()));
    if (uniqueEmails.size !== normalizedMembers.length) {
      return res.json({ success: false, message: "Duplicate member email found in team" });
    }

    const duplicateMember = normalizedMembers.find((member) =>
      registrations.some((reg) => reg.subEventId === subEventId && reg.email.toLowerCase() === member.email.toLowerCase())
    );
    if (duplicateMember) {
      return res.json({ success: false, message: `${duplicateMember.email} is already registered for this sub-event` });
    }

    const teamId = `TEAM-${subEventId}-${Date.now().toString(36)}-${Math.floor(100 + Math.random() * 900)}`;
    const resolvedTeamName = teamName || `Team ${teamId.slice(-3)}`;
    const created = [];
    let nextRegistrationId = registrations.reduce((max, item) => Math.max(max, Number(item.id) || 0), 0) + 1;
    normalizedMembers.forEach((member, index) => {
      const newReg = {
        id: nextRegistrationId++,
        name: member.name,
        college: member.college,
        department: member.department || "",
        email: member.email,
        mobile: member.mobile,
        subEventId,
        transactionId: transactionId || "",
        paymentStatus: "Pending",
        attendance: false,
        teamId,
        teamName: resolvedTeamName,
        teamSize: normalizedMembers.length,
        isTeamCaptain: index === 0,
        memberIndex: member.memberIndex
      };
      registrations.push(newReg);
      created.push(newReg);
    });

    store.saveRegistrations(registrations);
    logAudit({
      action: "Register Team",
      actor: "Public",
      role: "Student",
      details: `Team ${resolvedTeamName} (${created.length} members) for sub-event ${subEventId}`
    });
    return res.json({
      success: true,
      team: {
        teamId,
        teamName: resolvedTeamName,
        size: created.length
      },
      registrations: created
    });
  }

  const name = sanitizeString(req.body.name, 120);
  const college = sanitizeString(req.body.college, 120);
  const department = sanitizeString(req.body.department, 120);
  const email = sanitizeString(req.body.email, 120);
  const mobile = sanitizeString(req.body.mobile, 20);

  if (!name || !college || !email || !mobile) {
    return res.json({ success: false, message: "All fields required" });
  }
  if (!isValidEmail(email)) {
    return res.json({ success: false, message: "Invalid email" });
  }
  if (!isValidPhone(mobile)) {
    return res.json({ success: false, message: "Invalid mobile number" });
  }
  const exists = registrations.find(r => r.email === email && r.subEventId === parseInt(subEventId, 10));
  if (exists) {
    return res.json({ success: false, message: "Already registered for this sub-event" });
  }

  const newReg = {
    id: store.nextId("registrations"),
    name,
    college,
    department: department || "",
    email,
    mobile,
    subEventId,
    transactionId: transactionId || "",
    paymentStatus: "Pending",
    attendance: false
  };

  registrations.push(newReg);
  store.saveRegistrations(registrations);
  logAudit({
    action: "Register Student",
    actor: "Public",
    role: "Student",
    details: `Registration ${newReg.id} for sub-event ${newReg.subEventId}`
  });
  res.json({ success: true, registration: newReg });
});

/* =========================
   GET REGISTRATIONS BY SUB-EVENT
========================= */
app.get("/api/registrations/:subEventId", (req, res) => {
  const subEventId = toSafeInt(req.params.subEventId);
  if (!subEventId) return res.status(400).json({ success: false, message: "Invalid sub-event id" });
  const list = store.getRegistrations().filter(r => r.subEventId === subEventId);
  res.json(list);
});

/* =========================
   ADD OFFLINE REGISTRATION (Coordinator/President)
========================= */
app.post("/api/registrations/manual", rateLimit(40), verifyToken, allowRoles("Coordinator", "President"), (req, res) => {
  const subEventId = toSafeInt(req.body.subEventId);
  const name = sanitizeString(req.body.name, 120);
  const college = sanitizeString(req.body.college, 120);
  const department = sanitizeString(req.body.department, 120);
  const email = sanitizeString(req.body.email, 120);
  const mobile = sanitizeString(req.body.mobile, 20);
  const paymentStatusRaw = sanitizeString(req.body.paymentStatus, 20);
  const paymentStatus = ["Pending", "Paid", "Rejected"].includes(paymentStatusRaw) ? paymentStatusRaw : "Pending";

  if (!subEventId || !name || !college || !department || !email || !mobile) {
    return res.json({ success: false, message: "All fields required" });
  }
  if (!isValidEmail(email)) {
    return res.json({ success: false, message: "Invalid email" });
  }
  if (!isValidPhone(mobile)) {
    return res.json({ success: false, message: "Invalid mobile number" });
  }

  const subEvents = store.getSubEvents();
  const subEvent = subEvents.find(se => se.id === subEventId);
  if (!subEvent) {
    return res.status(404).json({ success: false, message: "Sub-event not found" });
  }
  let subEventChanged = false;
  if (ensureSubEventFields(subEvent)) subEventChanged = true;
  if (subEventChanged) store.saveSubEvents(subEvents);

  const registrations = store.getRegistrations();
  const exists = registrations.find(
    (reg) => reg.subEventId === subEventId && String(reg.email || "").toLowerCase() === email.toLowerCase()
  );
  if (exists) {
    return res.json({ success: false, message: "Student already registered for this sub-event" });
  }

  const newReg = {
    id: store.nextId("registrations"),
    name,
    college,
    department,
    email,
    mobile,
    subEventId,
    transactionId: "",
    paymentStatus,
    attendance: false
  };

  if (subEvent.participationType === "Team") {
    const teamName = sanitizeString(req.body.teamName, 120) || `Team-${subEventId}`;
    const teamId = sanitizeString(req.body.teamId, 80) || `MANUAL-${subEventId}-${Date.now().toString(36)}`;
    newReg.teamName = teamName;
    newReg.teamId = teamId;
    newReg.teamSize = 1;
    newReg.isTeamCaptain = false;
    newReg.memberIndex = 1;
  }

  registrations.push(newReg);
  store.saveRegistrations(registrations);
  logAudit({
    action: "Manual Registration",
    actor: req.user.id,
    role: req.user.role,
    details: `Registration ${newReg.id} for sub-event ${newReg.subEventId}`
  });
  res.json({ success: true, registration: newReg });
});

/* =========================
   UPDATE ATTENDANCE (Coordinator/President)
========================= */
app.put("/api/registrations/:id/attendance", rateLimit(60), verifyToken, allowRoles("Coordinator", "President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid registration id" });

  const attendance = Boolean(req.body.attendance);
  const registrations = store.getRegistrations();
  const reg = registrations.find((item) => item.id === id);
  if (!reg) return res.status(404).json({ success: false, message: "Registration not found" });

  reg.attendance = attendance;
  store.saveRegistrations(registrations);
  logAudit({
    action: "Update Attendance",
    actor: req.user.id,
    role: req.user.role,
    details: `Registration ${reg.id} attendance ${attendance ? "present" : "absent"}`
  });
  res.json({ success: true, registration: reg });
});

/* =========================
   DELETE REGISTRATION (Coordinator/President)
========================= */
app.delete("/api/registrations/:id", rateLimit(30), verifyToken, allowRoles("Coordinator", "President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid registration id" });

  const registrations = store.getRegistrations();
  const index = registrations.findIndex((item) => item.id === id);
  if (index === -1) return res.status(404).json({ success: false, message: "Registration not found" });

  const [removed] = registrations.splice(index, 1);
  store.saveRegistrations(registrations);

  // Keep payment data consistent when a linked registration is deleted.
  const payments = store.getPayments();
  let paymentsChanged = false;
  const replacement = removed && removed.transactionId
    ? registrations.find((item) => item.transactionId === removed.transactionId)
    : null;
  payments.forEach((payment) => {
    if (Array.isArray(payment.registrationIds)) {
      const existingIds = payment.registrationIds.map((rid) => Number(rid)).filter(Boolean);
      const nextIds = existingIds.filter((rid) => rid !== id);
      if (nextIds.length !== existingIds.length) {
        payment.registrationIds = nextIds;
        paymentsChanged = true;
      }
      const primaryId = Number(payment.registrationId);
      if (primaryId === id || (nextIds.length > 0 && !nextIds.includes(primaryId))) {
        payment.registrationId = nextIds[0] || (replacement ? replacement.id : null);
        paymentsChanged = true;
      }
    } else if (Number(payment.registrationId) === id) {
      payment.registrationId = replacement ? replacement.id : null;
      paymentsChanged = true;
    }
  });
  if (paymentsChanged) {
    store.savePayments(payments);
  }

  logAudit({
    action: "Delete Registration",
    actor: req.user.id,
    role: req.user.role,
    details: `Registration ${id} removed from sub-event ${removed ? removed.subEventId : ""}`
  });
  res.json({ success: true, message: "Registration deleted" });
});

/* =========================
   PAYMENT: GET CURRENT QR
========================= */
app.get("/api/payments/qr", (req, res) => {
  const config = store.getPaymentConfig();
  res.json({ success: true, qrPath: config.qrPath || null });
});

/* =========================
   PAYMENT: UPLOAD QR (President)
========================= */
app.post("/api/payments/qr", rateLimit(20), verifyToken, allowRoles("President"), (req, res, next) => {
  uploadUPI.single("qr")(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, message: err.message || "Upload failed" });
    if (!req.file) return res.status(400).json({ success: false, message: "No file" });

    const qrPath = "/uploads/upi/" + path.basename(req.file.path);
    store.savePaymentConfig({ qrPath });
    logAudit({
      action: "Upload UPI QR",
      actor: req.user.id,
      role: req.user.role,
      details: "UPI QR updated"
    });
    res.json({ success: true, qrPath });
  });
});

/* =========================
   PAYMENT: CREATE RAZORPAY ORDER
========================= */
app.post("/api/payments/create-order", rateLimit(30), async (req, res) => {
  if (!isRazorpayConfigured()) {
    return res.status(503).json({
      success: false,
      message: "Razorpay is not configured on server"
    });
  }

  const rawIds = Array.isArray(req.body.registrationIds)
    ? req.body.registrationIds
    : [req.body.registrationId];
  const registrationIds = Array.from(
    new Set(rawIds.map((id) => toSafeInt(id)).filter(Boolean))
  );
  if (registrationIds.length === 0) {
    return res.status(400).json({ success: false, message: "Registration ID is required" });
  }

  const registrations = store.getRegistrations();
  const selected = registrationIds
    .map((id) => registrations.find((reg) => reg.id === id))
    .filter(Boolean);
  if (selected.length !== registrationIds.length) {
    return res.status(404).json({ success: false, message: "One or more registrations not found" });
  }

  const subEventId = toSafeInt(selected[0].subEventId);
  if (!subEventId || selected.some((reg) => toSafeInt(reg.subEventId) !== subEventId)) {
    return res.status(400).json({ success: false, message: "Selected registrations must belong to one sub-event" });
  }
  if (selected.some((reg) => sanitizeString(reg.paymentStatus, 20) === "Paid")) {
    return res.status(400).json({ success: false, message: "Payment already completed for selected registration(s)" });
  }

  const teamIds = selected.map((reg) => sanitizeString(reg.teamId, 80)).filter(Boolean);
  if (teamIds.length > 0 && new Set(teamIds).size > 1) {
    return res.status(400).json({ success: false, message: "Team payment can include only one team at a time" });
  }

  const subEvent = store.getSubEvents().find((item) => item.id === subEventId);
  if (!subEvent) {
    return res.status(404).json({ success: false, message: "Sub-event not found" });
  }
  const amountPaise = toMoneyPaise(subEvent.fee);
  if (amountPaise <= 0) {
    return res.status(400).json({ success: false, message: "Invalid sub-event fee for payment" });
  }

  try {
    const receipt = `sub-${subEventId}-${Date.now()}`;
    const order = await createRazorpayOrder(amountPaise, receipt, {
      subEventId: String(subEventId),
      registrationCount: String(registrationIds.length)
    });

    const payments = store.getPayments();
    const payment = {
      id: store.nextId("payments"),
      transactionId: "",
      registrationId: registrationIds[0],
      registrationIds,
      subEventId,
      status: "Pending",
      method: "Razorpay",
      razorpayOrderId: order.id,
      amountPaise: order.amount,
      amount: Number((order.amount / 100).toFixed(2)),
      currency: sanitizeString(order.currency, 12) || RAZORPAY_CURRENCY,
      createdAt: new Date().toISOString()
    };
    payments.push(payment);
    store.savePayments(payments);

    logAudit({
      action: "Create Razorpay Order",
      actor: "Public",
      role: "Student",
      details: `Order ${order.id} for registrations ${registrationIds.join(",")}`
    });

    res.json({
      success: true,
      keyId: RAZORPAY_KEY_ID,
      order: {
        id: order.id,
        amount: order.amount,
        currency: order.currency
      },
      payment
    });
  } catch (err) {
    res.status(502).json({ success: false, message: err.message || "Unable to create payment order" });
  }
});

/* =========================
   PAYMENT: VERIFY RAZORPAY SIGNATURE
========================= */
app.post("/api/payments/verify", rateLimit(40), (req, res) => {
  if (!isRazorpayConfigured()) {
    return res.status(503).json({
      success: false,
      message: "Razorpay is not configured on server"
    });
  }

  const orderId = sanitizeString(req.body.razorpay_order_id, 120);
  const paymentId = sanitizeString(req.body.razorpay_payment_id, 120);
  const signature = sanitizeString(req.body.razorpay_signature, 180);
  if (!orderId || !paymentId || !signature) {
    return res.status(400).json({ success: false, message: "Missing Razorpay verification fields" });
  }

  const payments = store.getPayments();
  const payment = payments.find((item) => item.razorpayOrderId === orderId);
  if (!payment) {
    return res.status(404).json({ success: false, message: "Payment order not found" });
  }

  if (payment.status === "Verified" && payment.transactionId === paymentId) {
    return res.json({ success: true, payment });
  }

  const expected = crypto
    .createHmac("sha256", RAZORPAY_KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");
  if (expected !== signature) {
    payment.status = "Rejected";
    payment.failureReason = "Signature mismatch";
    payment.verifiedAt = new Date().toISOString();
    store.savePayments(payments);
    return res.status(400).json({ success: false, message: "Payment verification failed" });
  }

  payment.status = "Verified";
  payment.transactionId = paymentId;
  payment.razorpayPaymentId = paymentId;
  payment.razorpaySignature = signature;
  payment.verifiedAt = new Date().toISOString();

  const registrationIds = Array.isArray(payment.registrationIds) && payment.registrationIds.length > 0
    ? payment.registrationIds.map((id) => toSafeInt(id)).filter(Boolean)
    : [toSafeInt(payment.registrationId)].filter(Boolean);
  const registrationIdSet = new Set(registrationIds);
  const registrations = store.getRegistrations();
  let updatedCount = 0;
  registrations.forEach((reg) => {
    if (registrationIdSet.has(reg.id)) {
      reg.paymentStatus = "Paid";
      reg.transactionId = paymentId;
      updatedCount += 1;
    }
  });

  store.savePayments(payments);
  if (updatedCount > 0) {
    store.saveRegistrations(registrations);
  }

  logAudit({
    action: "Verify Razorpay Payment",
    actor: "Public",
    role: "Student",
    details: `Order ${orderId} verified; regs updated ${updatedCount}`
  });
  res.json({ success: true, payment, updatedRegistrations: updatedCount });
});

/* =========================
   PAYMENT: SUBMIT TRANSACTION (DEPRECATED)
========================= */
app.post("/api/payments/submit", rateLimit(30), (req, res) => {
  res.status(410).json({
    success: false,
    message: "Manual transaction submission is disabled. Please use Razorpay checkout."
  });
});

/* =========================
   PAYMENT: LIST (President / Faculty)
========================= */
app.get("/api/payments", verifyToken, allowRoles("President", "Faculty"), (req, res) => {
  const payments = store.getPayments();
  const sorted = payments.slice().sort((a, b) => {
    const ta = Date.parse(a.createdAt || "") || 0;
    const tb = Date.parse(b.createdAt || "") || 0;
    return tb - ta;
  });
  res.json(sorted);
});

/* =========================
   PAYMENT: UPDATE STATUS (President / Faculty)
========================= */
app.post("/api/payments/:id/status", rateLimit(40), verifyToken, allowRoles("President", "Faculty"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid payment id" });
  const status = sanitizeString(req.body.status, 20);
  if (!status || !["Verified", "Rejected"].includes(status)) {
    return res.json({ success: false, message: "Invalid status" });
  }

  const payments = store.getPayments();
  const payment = payments.find(p => p.id === id);
  if (!payment) {
    return res.json({ success: false, message: "Payment not found" });
  }
  if (sanitizeString(payment.method, 20) === "Razorpay") {
    return res.status(400).json({
      success: false,
      message: "Razorpay payments are auto-verified and cannot be manually updated"
    });
  }

  payment.status = status;
  payment.verifiedAt = new Date().toISOString();

  const registrations = store.getRegistrations();
  let updated = false;
  if (payment.transactionId) {
    registrations.forEach(r => {
      if (r.transactionId === payment.transactionId) {
        r.paymentStatus = status === "Verified" ? "Paid" : "Rejected";
        updated = true;
      }
    });
  }
  if (!updated && payment.registrationId) {
    const reg = registrations.find(r => r.id === Number(payment.registrationId));
    if (reg) {
      reg.paymentStatus = status === "Verified" ? "Paid" : "Rejected";
      if (payment.transactionId) reg.transactionId = payment.transactionId;
      updated = true;
    }
  }

  store.savePayments(payments);
  if (updated) store.saveRegistrations(registrations);
  logAudit({
    action: "Verify Payment",
    actor: req.user.id,
    role: req.user.role,
    details: `Payment ${payment.id} -> ${status}`
  });
  res.json({ success: true, payment });
});

/* =========================
   APPLY FOR ROLE (Coordinator / Volunteer)
========================= */
app.post("/api/apply-role", rateLimit(40), (req, res) => {
  const name = sanitizeString(req.body.name, 120);
  const email = sanitizeString(req.body.email, 120);
  const role = sanitizeString(req.body.role, 20);
  const subEventId = toSafeInt(req.body.subEventId);

  if (!name || !email || !role || !subEventId) {
    return res.json({ success: false, message: "All fields required" });
  }
  if (!["Coordinator", "Volunteer"].includes(role)) {
    return res.json({ success: false, message: "Invalid role" });
  }
  if (!isValidEmail(email)) {
    return res.json({ success: false, message: "Invalid email" });
  }
  const subEventExists = store.getSubEvents().some(se => se.id === subEventId);
  if (!subEventExists) {
    return res.status(404).json({ success: false, message: "Sub-event not found" });
  }

  const roleApplications = store.getApplications();
  const exists = roleApplications.find(a =>
    a.email === email && a.role === role && a.subEventId === subEventId
  );

  if (exists) {
    return res.json({ success: false, message: "Already applied" });
  }

  const newApp = {
    id: store.nextId("applications"),
    name,
    email,
    role,
    subEventId,
    status: "Pending"
  };

  roleApplications.push(newApp);
  store.saveApplications(roleApplications);
  logAudit({
    action: "Apply Role",
    actor: "Public",
    role: "Student",
    details: `${newApp.role} application ${newApp.id} for sub-event ${newApp.subEventId}`
  });
  res.json({ success: true, application: newApp });
});

/* =========================
   GET ROLE APPLICATIONS BY SUB-EVENT
========================= */
app.get("/api/applications/:subEventId", (req, res) => {
  const subEventId = toSafeInt(req.params.subEventId);
  if (!subEventId) return res.status(400).json({ success: false, message: "Invalid sub-event id" });
  const list = store.getApplications().filter(a => a.subEventId === subEventId);
  res.json(list);
});

/* =========================
   APPROVE / REJECT ROLE
========================= */
app.post("/api/applications/:id/status", rateLimit(40), verifyToken, allowRoles("Faculty", "President"), (req, res) => {
  const id = toSafeInt(req.params.id);
  if (!id) return res.status(400).json({ success: false, message: "Invalid application id" });
  const status = sanitizeString(req.body.status, 20);
  if (!["Approved", "Rejected", "Pending"].includes(status)) {
    return res.json({ success: false, message: "Invalid status" });
  }

  const roleApplications = store.getApplications();
  const appItem = roleApplications.find(a => a.id === id);
  if (!appItem) {
    return res.json({ success: false, message: "Application not found" });
  }

  const users = store.getUsers();

  if (status === "Approved") {
    const shouldGenerate = !appItem.generatedUsername || !appItem.generatedPassword || !appItem.assignedUserId;
    if (shouldGenerate) {
      const username = generateUsername(appItem.role, appItem.subEventId, users);
      if (!username) {
        return res.json({ success: false, message: "Unable to generate username" });
      }
      const plainPassword = generatePassword();
      const hashed = bcrypt.hashSync(plainPassword, 10);
      const newUser = {
        id: store.nextId("users"),
        username,
        password: hashed,
        role: appItem.role,
        subEventId: appItem.subEventId,
        createdAt: new Date().toISOString()
      };
      users.push(newUser);
      store.saveUsers(users);
      appItem.generatedUsername = username;
      appItem.generatedPassword = plainPassword;
      appItem.assignedUserId = newUser.id;
    }
  } else if (status === "Rejected") {
    if (appItem.assignedUserId) {
      const remaining = users.filter(u => u.id !== appItem.assignedUserId);
      store.saveUsers(remaining);
    }
    appItem.generatedUsername = "";
    appItem.generatedPassword = "";
    appItem.assignedUserId = null;
  }

  appItem.status = status;
  store.saveApplications(roleApplications);
  logAudit({
    action: "Update Role Application",
    actor: req.user.id,
    role: req.user.role,
    details: `Application ${appItem.id} -> ${status}`
  });
  res.json({ success: true, application: appItem });
});

/* =========================
   AUDIT LOG (President / Faculty)
========================= */
app.get("/api/audit", verifyToken, allowRoles("President", "Faculty"), (req, res) => {
  const limit = Math.max(1, Math.min(200, parseInt(req.query.limit || "50", 10)));
  const q = String(req.query.q || "").trim().toLowerCase();
  const role = String(req.query.role || "").trim().toLowerCase();
  const action = String(req.query.action || "").trim().toLowerCase();
  const actor = String(req.query.actor || "").trim().toLowerCase();
  const fromRaw = String(req.query.from || "").trim();
  const toRaw = String(req.query.to || "").trim();
  const fromTs = fromRaw ? Date.parse(fromRaw) : null;
  const toTs = toRaw ? Date.parse(toRaw) : null;

  const logs = store.getAuditLog();
  const filtered = logs.filter((entry) => {
    const entryRole = String(entry.role || "").toLowerCase();
    const entryAction = String(entry.action || "").toLowerCase();
    const entryActor = String(entry.actor || "").toLowerCase();
    const entryDetails = String(entry.details || "").toLowerCase();
    const entryAt = Date.parse(entry.at || "") || 0;

    if (role && entryRole !== role) return false;
    if (action && !entryAction.includes(action)) return false;
    if (actor && entryActor !== actor) return false;
    if (fromTs && entryAt < fromTs) return false;
    if (toTs && entryAt > toTs) return false;

    if (q) {
      const haystack = `${entryAction} ${entryDetails} ${entryRole} ${entryActor}`;
      if (!haystack.includes(q)) return false;
    }

    return true;
  });

  const sorted = filtered.slice().sort((a, b) => {
    const ta = Date.parse(a.at || "") || 0;
    const tb = Date.parse(b.at || "") || 0;
    return tb - ta;
  });
  res.json(sorted.slice(0, limit));
});

/* =========================
   ANALYTICS (President / Faculty)
========================= */
app.get("/api/analytics", verifyToken, allowRoles("President", "Faculty"), (req, res) => {
  const events = store.getEvents();
  const subEvents = store.getSubEvents();
  const registrations = store.getRegistrations();
  const applications = store.getApplications();
  const payments = store.getPayments();

  const validEventIds = new Set(events.map(e => e.id));
  const filteredSubEvents = subEvents.filter(se => validEventIds.has(se.eventId));
  const validSubEventIds = new Set(filteredSubEvents.map(se => se.id));
  const filteredRegistrations = registrations.filter(r => validSubEventIds.has(r.subEventId));
  const filteredApplications = applications.filter(a => validSubEventIds.has(a.subEventId));

  const regBySub = {};
  filteredRegistrations.forEach(r => {
    const key = String(r.subEventId);
    regBySub[key] = (regBySub[key] || 0) + 1;
  });

  const topSubEvents = filteredSubEvents
    .map(se => ({
      id: se.id,
      name: se.name,
      eventId: se.eventId,
      registrations: regBySub[String(se.id)] || 0
    }))
    .sort((a, b) => b.registrations - a.registrations)
    .slice(0, 5);

  const appStatusCounts = filteredApplications.reduce((acc, a) => {
    const key = a.status || "Pending";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  const paymentStatusCounts = payments.reduce((acc, p) => {
    const key = p.status || "Pending";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  res.json({
    events: events.length,
    subEvents: filteredSubEvents.length,
    registrations: filteredRegistrations.length,
    applications: filteredApplications.length,
    topSubEvents,
    appStatusCounts,
    paymentStatusCounts
  });
});

/* =========================
   BASIC HEALTH + ROOT
========================= */
app.get("/api/health", (req, res) => {
  res.json({ ok: true, at: new Date().toISOString() });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(frontendPath, "index.html"));
});

app.listen(PORT, HOST, () => {
  console.log(`Server running on http://${HOST}:${PORT}`);
});
