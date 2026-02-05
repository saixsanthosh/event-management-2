const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");

const DATA_DIR = path.join(__dirname, "data");
const FILES = {
  users: "users.json",
  events: "events.json",
  subevents: "subevents.json",
  registrations: "registrations.json",
  applications: "applications.json",
  paymentConfig: "payment-config.json",
  payments: "payments.json",
  audit: "audit.json",
};

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function getPath(name) {
  ensureDataDir();
  return path.join(DATA_DIR, FILES[name] || name);
}

function read(name) {
  const filePath = getPath(name);
  if (!fs.existsSync(filePath)) return null;
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

function write(name, data) {
  const filePath = getPath(name);
  ensureDataDir();
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function seedDefaultUsers() {
  const filePath = getPath("users");
  if (fs.existsSync(filePath)) return;
  const defaults = [
    { id: 1, username: "president", password: bcrypt.hashSync("1234", 10), role: "President" },
    { id: 2, username: "faculty", password: bcrypt.hashSync("1234", 10), role: "Faculty" },
    { id: 3, username: "hod", password: bcrypt.hashSync("1234", 10), role: "HOD" },
    { id: 4, username: "vp", password: bcrypt.hashSync("1234", 10), role: "VP" },
    { id: 5, username: "dean", password: bcrypt.hashSync("1234", 10), role: "Dean" },
    { id: 6, username: "coordinator", password: bcrypt.hashSync("1234", 10), role: "Coordinator" },
    { id: 7, username: "volunteer", password: bcrypt.hashSync("1234", 10), role: "Volunteer" },
  ];
  write("users", defaults);
}

// Initialize data dir and seed users if needed
ensureDataDir();
seedDefaultUsers();

// --- Users
function getUsers() {
  const data = read("users");
  return Array.isArray(data) ? data : [];
}

function saveUsers(users) {
  write("users", users);
}

// --- Events
function getEvents() {
  const data = read("events");
  return Array.isArray(data) ? data : [];
}

function saveEvents(events) {
  write("events", events);
}

// --- Sub-events
function getSubEvents() {
  const data = read("subevents");
  return Array.isArray(data) ? data : [];
}

function saveSubEvents(subevents) {
  write("subevents", subevents);
}

// --- Registrations
function getRegistrations() {
  const data = read("registrations");
  return Array.isArray(data) ? data : [];
}

function saveRegistrations(registrations) {
  write("registrations", registrations);
}

// --- Role applications
function getApplications() {
  const data = read("applications");
  return Array.isArray(data) ? data : [];
}

function saveApplications(applications) {
  write("applications", applications);
}

// --- Payment config
function getPaymentConfig() {
  const data = read("paymentConfig");
  return data && typeof data === "object" ? data : {};
}

function savePaymentConfig(config) {
  write("paymentConfig", config || {});
}

// --- Payments
function getPayments() {
  const data = read("payments");
  return Array.isArray(data) ? data : [];
}

function savePayments(payments) {
  write("payments", payments);
}

// --- Audit log
function getAuditLog() {
  const data = read("audit");
  return Array.isArray(data) ? data : [];
}

function saveAuditLog(logs) {
  write("audit", logs);
}

function appendAuditLog(entry) {
  const logs = getAuditLog();
  logs.push(entry);
  saveAuditLog(logs);
}

// --- IDs
function nextId(collection) {
  const list = read(collection) || [];
  if (list.length === 0) return 1;
  const max = Math.max(...list.map((x) => x.id));
  return max + 1;
}

module.exports = {
  getUsers,
  saveUsers,
  getEvents,
  saveEvents,
  getSubEvents,
  saveSubEvents,
  getRegistrations,
  saveRegistrations,
  getApplications,
  saveApplications,
  getPaymentConfig,
  savePaymentConfig,
  getPayments,
  savePayments,
  getAuditLog,
  saveAuditLog,
  appendAuditLog,
  nextId,
  read,
  write,
};
