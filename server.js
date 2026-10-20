/**
 * Today's 15 backend
 *  - PayPal subscription verification ($4.99/month), re-checked hourly (no webhook)
 *  - Photo -> 15-minute workout via Groq (OpenAI-compatible vision API)
 *  - Email/password accounts; Pro follows the account across devices
 *  - Postgres (Render) for users, subscriptions and free-tier usage
 *
 * Required env vars (set in Render):
 *   DATABASE_URL           Postgres connection string
 *   GROQ_API_KEY           Groq API key
 *   JWT_SECRET             Long random string used to sign Pro tokens
 *   PAYPAL_CLIENT_ID       PayPal app client id
 *   PAYPAL_CLIENT_SECRET   PayPal app secret
 *   PAYPAL_PLAN_ID         The $4.99/month plan id (starts with P-)
 * Optional:
 *   PAYPAL_ENV             "sandbox" (default) or "live"
 *   GROQ_MODEL             Defaults to a Llama 4 vision model; check Groq's docs for current names
 *   ALLOWED_ORIGIN         Comma-separated list of allowed site origins (recommended)
 *   FREE_DAILY_LIMIT       Free workouts per day (default 1)
 *   PRO_DAILY_LIMIT        Pro workouts per day (default 20)
 *   PGSSL                  "false" to disable SSL for the database (default: on)
 */
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const {
  DATABASE_URL, GROQ_API_KEY, JWT_SECRET,
  PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_PLAN_ID,
} = process.env;
const PAYPAL_BASE = process.env.PAYPAL_ENV === "live"
  ? "https://api-m.paypal.com"
  : "https://api-m.sandbox.paypal.com";
const GROQ_MODEL = process.env.GROQ_MODEL || "meta-llama/llama-4-scout-17b-16e-instruct";
const FREE_LIMIT = parseInt(process.env.FREE_DAILY_LIMIT || "1", 10);
const PRO_LIMIT = parseInt(process.env.PRO_DAILY_LIMIT || "20", 10);
const MAX_DEVICES_PER_SUB = 5;
const IP_LIMIT = parseInt(process.env.IP_DAILY_LIMIT || "15", 10);

for (const [k, v] of Object.entries({ DATABASE_URL, GROQ_API_KEY, JWT_SECRET, PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_PLAN_ID })) {
  if (!v) console.warn(`[config] Missing env var: ${k}`);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSL === "false" ? false : { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS subscriptions (
      subscription_id TEXT PRIMARY KEY,
      plan_id TEXT NOT NULL,
      status TEXT NOT NULL,
      payer_email TEXT,
      next_billing_time TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sub_devices (
      subscription_id TEXT NOT NULL REFERENCES subscriptions(subscription_id) ON DELETE CASCADE,
      device_id TEXT NOT NULL,
      PRIMARY KEY (subscription_id, device_id)
    );
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id);
    ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS checked_at TIMESTAMPTZ NOT NULL DEFAULT now();
    CREATE TABLE IF NOT EXISTS usage (
      key TEXT NOT NULL,
      day DATE NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (key, day)
    );
  `);
}

/* ---------- PayPal helpers ---------- */
let ppToken = { value: null, exp: 0 };
async function paypalToken() {
  if (ppToken.value && Date.now() < ppToken.exp) return ppToken.value;
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString("base64");
  const r = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  if (!r.ok) throw new Error(`PayPal auth failed (${r.status})`);
  const d = await r.json();
  ppToken = { value: d.access_token, exp: Date.now() + (d.expires_in - 60) * 1000 };
  return ppToken.value;
}
async function paypalFetch(path, opts = {}) {
  const token = await paypalToken();
  return fetch(`${PAYPAL_BASE}${path}`, {
    ...opts,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
}

/* ---------- App ---------- */
const app = express();
app.set("trust proxy", 1); // Render sits behind a proxy
app.use(express.json({ limit: "6mb" }));
const origins = (process.env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
app.use(cors({
  origin: origins.length ? origins : true,
  allowedHeaders: ["Content-Type", "Authorization", "x-device-id", "x-tz"],
}));
app.use(rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false }));

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  console.error(e);
  res.status(500).json({ error: "Server error. Please try again." });
});

app.use(express.static(require("path").join(__dirname, "public"))); // serves public/index.html
app.get("/health", (_req, res) => res.json({ ok: true }));

/* ---------- Auth helpers ---------- */
function deviceIdOf(req) {
  const d = String(req.get("x-device-id") || "").trim();
  return /^[A-Za-z0-9_-]{8,64}$/.test(d) ? d : null;
}
/* ---------- Accounts ---------- */
const crypto = require("crypto");
const scrypt = require("util").promisify(crypto.scrypt);
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return `${salt.toString("hex")}:${(await scrypt(pw, salt, 64)).toString("hex")}`;
}
async function checkPw(pw, stored) {
  try {
    const [s, h] = stored.split(":");
    return crypto.timingSafeEqual(await scrypt(pw, Buffer.from(s, "hex"), 64), Buffer.from(h, "hex"));
  } catch { return false; }
}
function authUid(req) {
  const h = req.get("authorization") || "";
  if (!h.startsWith("Bearer ")) return null;
  try { const { uid } = jwt.verify(h.slice(7), JWT_SECRET); return Number.isInteger(uid) ? uid : null; }
  catch { return null; }
}
const issue = (u) => ({
  token: jwt.sign({ uid: u.id }, JWT_SECRET, { expiresIn: "60d" }),
  user: { id: u.id, email: u.email, name: u.name },
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many attempts. Try again in a few minutes." },
});
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

app.post("/api/auth/signup", authLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const pw = String(req.body.password || "");
  const name = String(req.body.name || "").trim().slice(0, 40);
  if (!EMAIL_RE.test(email) || email.length > 254) return res.status(400).json({ error: "Enter a valid email address." });
  if (pw.length < 8 || pw.length > 128) return res.status(400).json({ error: "Use a password with at least 8 characters." });
  try {
    const { rows } = await pool.query("INSERT INTO users (email, pass_hash, name) VALUES ($1,$2,$3) RETURNING id, email, name",
      [email, await hashPw(pw), name]);
    res.json(issue(rows[0]));
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "An account with this email already exists. Try logging in." });
    throw e;
  }
}));

app.post("/api/auth/login", authLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const pw = String(req.body.password || "");
  const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  const u = rows[0];
  if (!u || !(await checkPw(pw, u.pass_hash))) return res.status(401).json({ error: "Incorrect email or password." });
  res.json(issue(u));
}));

async function getPro(req) {
  const uid = authUid(req);
  if (!uid) return null;
  try {
    const { rows } = await pool.query(
      "SELECT * FROM subscriptions WHERE user_id=$1 ORDER BY (status='ACTIVE') DESC, updated_at DESC LIMIT 1", [uid]);
    const row = rows[0];
    if (!row) return null;
    // No webhook: re-check PayPal at most once an hour so cancellations are noticed
    if (Date.now() - new Date(row.checked_at).getTime() > 60 * 60 * 1000) {
      try {
        const r = await paypalFetch(`/v1/billing/subscriptions/${row.subscription_id}`);
        if (r.ok) {
          const s = await r.json();
          const next = s.billing_info && s.billing_info.next_billing_time || null;
          await pool.query("UPDATE subscriptions SET status=$1, next_billing_time=$2, checked_at=now(), updated_at=now() WHERE subscription_id=$3", [s.status, next, row.subscription_id]);
          row.status = s.status;
        }
      } catch (e) { console.error("[paypal] recheck failed:", e.message); }
    }
    return row.status === "ACTIVE" ? row : null;
  } catch { return null; }
}

/* ---------- PayPal: verify a subscription after checkout (account required) ---------- */
app.post("/api/paypal/verify", wrap(async (req, res) => {
  const uid = authUid(req);
  if (!uid) return res.status(401).json({ error: "Please sign in first." });
  const subscriptionId = String(req.body.subscriptionId || "");
  if (!/^I-[A-Z0-9]{6,40}$/.test(subscriptionId)) return res.status(400).json({ error: "Invalid subscription id." });

  const r = await paypalFetch(`/v1/billing/subscriptions/${subscriptionId}`);
  if (!r.ok) return res.status(402).json({ error: "Could not verify this subscription with PayPal." });
  const s = await r.json();
  if (s.plan_id !== PAYPAL_PLAN_ID) return res.status(402).json({ error: "Subscription is for a different plan." });
  if (s.status !== "ACTIVE") return res.status(402).json({ error: `Subscription is ${s.status}. If you just paid, try again in a moment.` });

  const ex = await pool.query("SELECT user_id FROM subscriptions WHERE subscription_id=$1", [subscriptionId]);
  if (ex.rows[0] && ex.rows[0].user_id && ex.rows[0].user_id !== uid) return res.status(403).json({ error: "This subscription belongs to another account." });

  const email = s.subscriber && s.subscriber.email_address || null;
  const next = s.billing_info && s.billing_info.next_billing_time || null;
  await pool.query(
    `INSERT INTO subscriptions (subscription_id, plan_id, status, payer_email, next_billing_time, user_id)
     VALUES ($1,$2,'ACTIVE',$3,$4,$5)
     ON CONFLICT (subscription_id) DO UPDATE SET status='ACTIVE', payer_email=EXCLUDED.payer_email,
       next_billing_time=EXCLUDED.next_billing_time, user_id=EXCLUDED.user_id, updated_at=now(), checked_at=now()`,
    [subscriptionId, s.plan_id, email, next, uid]
  );
  res.json({ pro: true, nextBillingTime: next });
}));

/* ---------- Who am I + Pro status ---------- */
app.get("/api/status", wrap(async (req, res) => {
  const uid = authUid(req);
  if (!uid) return res.status(401).json({ error: "Not signed in." });
  const { rows } = await pool.query("SELECT id, email, name FROM users WHERE id=$1", [uid]);
  if (!rows[0]) return res.status(401).json({ error: "Not signed in." });
  const pro = await getPro(req);
  const used = await usedToday([`u:${uid}`], dayOf(tzOf(req)));
  res.json({ user: rows[0], pro: !!pro, used, freeDailyLimit: FREE_LIMIT, proDailyLimit: PRO_LIMIT });
}));

/* ---------- Photo -> workout ---------- */
const FALLBACK = [
  ["Marching in place", "Lift knees to hip height, swing your arms.", "warmup"],
  ["Standing hip circles", "Big slow circles, then switch direction.", "warmup"],
  ["Bodyweight squats", "Sit back, chest tall, knees over toes.", "strength"],
  ["Incline push-ups", "Hands on a wall or desk, body in one line.", "strength"],
  ["Reverse lunges", "Step back, drop the knee, switch sides.", "strength"],
  ["Glute bridges", "Squeeze at the top, ribs down.", "strength"],
  ["Plank", "Forearms down, belly braced, breathe.", "core"],
  ["Chair dips", "Hands on a sturdy chair, elbows back.", "strength"],
  ["Side-step squats", "Stay low, step wide, keep tension.", "cardio"],
  ["Dead bugs", "Lower back pressed down, move slowly.", "core"],
  ["Superman holds", "Lift chest and legs, long neck.", "strength"],
  ["Fast feet", "Quick light steps, stay on the balls of your feet.", "cardio"],
  ["Mountain climbers", "Hips low, drive knees in steadily.", "cardio"],
  ["Cat-cow stretch", "Round, then arch, move with your breath.", "cooldown"],
  ["Deep breathing", "In through the nose, long slow exhale.", "cooldown"],
].map(([n, c, t]) => ({ n, c, t }));

const TYPES = ["warmup", "strength", "cardio", "core", "mobility", "cooldown"];
const GOALS = ["Energy", "Strength", "Mobility", "Cardio"];
const AVOIDS = ["Knees", "Lower back", "Shoulders", "Wrists"];
const BANNED = /\b(fat|obese|overweight|underweight|skinny|thin|lean|chubby|flab\w*|curvy|attractive|sexy|pounds|lbs|bmi|body ?fat|diagnos\w*)\b/i;
const clean = (s, n) => { s = String(s || "").trim().slice(0, n); return BANNED.test(s) ? "" : s; };

function parsePlan(text) {
  const a = text.indexOf("{"), b = text.lastIndexOf("}");
  if (a < 0 || b < a) throw new Error("No JSON in model output");
  const j = JSON.parse(text.slice(a, b + 1));
  if (j.framing && j.framing.ok === false) return { retake: true, tip: clean(j.framing.tip, 160) || "I couldn’t see a person clearly. Try a brighter, full-body photo." };
  const moves = (Array.isArray(j.moves) ? j.moves : [])
    .filter((m) => m && m.n && clean(m.n, 60))
    .map((m) => ({ n: clean(m.n, 60), c: clean(m.c, 120), t: TYPES.includes(m.t) ? m.t : "strength" }));
  while (moves.length < 15) moves.push(FALLBACK[moves.length]);
  return {
    note: clean(j.note, 200) || "Here is a balanced 15 for today.",
    focus: clean(j.focus, 60),
    obs: (Array.isArray(j.observations) ? j.observations : []).map((o) => clean(o, 150)).filter(Boolean).slice(0, 4),
    tip: clean(j.framing && j.framing.tip, 160),
    moves: moves.slice(0, 15),
  };
}

function dayOf(tz) { return new Intl.DateTimeFormat("en-CA", { timeZone: tz }).format(new Date()); }
function tzOf(req) {
  const tz = String(req.get("x-tz") || "UTC");
  try { new Intl.DateTimeFormat("en-CA", { timeZone: tz }); return tz; } catch { return "UTC"; }
}
async function bump(key, day) {
  await pool.query(
    `INSERT INTO usage (key, day, count) VALUES ($1, $2::date, 1)
     ON CONFLICT (key, day) DO UPDATE SET count = usage.count + 1`, [key, day]);
}
async function usedToday(keys, day) {
  const { rows } = await pool.query("SELECT COALESCE(MAX(count),0) AS c FROM usage WHERE key = ANY($1) AND day = $2::date", [keys, day]);
  return rows[0].c;
}

const SYSTEM =
`You are an expert personal trainer and movement coach. You look at one photo and design a safe, personalised 15-minute no-equipment workout.
RULES:
- Judge only practical things: posture and stance, the space and furniture around the person, footwear and flooring. Use hedged wording ("seems", "may").
- NEVER comment on weight, body fat, shape, size, muscle, attractiveness, age, or health conditions. No medical claims or diagnoses.
- If no person is visible or the image is unusable, set framing.ok=false and give a friendly retake tip. If the person is visible but cropped or dark, keep framing.ok=true and put a short improvement tip in framing.tip.
- Respect the user's level, goal, space and areas to avoid. For avoided areas, choose gentler alternatives and no direct loading on them.
- Small space: no jumping, no big lateral travel. Hard floor: avoid kneeling moves. If you can see a chair, wall, desk or stairs, use them for incline push-ups, step-ups or supported moves.
- If posture cues appear (e.g. rounded shoulders, head forward, weight shifted to one side), include 1-2 matching mobility or strengthening moves.
- Avoid repeating the recently done moves listed by the user. Vary the pattern day to day.
- Exactly 15 moves in this order: 2 warmup, 11 main (mix of strength, cardio, core per goal and level), 2 cooldown. Each move is performed for 40 seconds. Cues are max 14 words.
- Goal guide: Energy = lively mixed circuit; Strength = more strength and core, controlled tempo; Mobility = flowing mobility plus light strength; Cardio = more heart-rate raising moves.
Return ONLY valid JSON, no backticks:
{"framing":{"ok":true,"tip":""},"observations":["2 to 4 practical, non-judgmental notes"],"focus":"short focus title","note":"one warm sentence about today's plan","moves":[{"n":"name","c":"cue","t":"warmup|strength|cardio|core|mobility|cooldown"}]}`;

async function callGroq(messages, json) {
  const body = { model: GROQ_MODEL, temperature: 0.6, max_tokens: 1600, messages };
  if (json) body.response_format = { type: "json_object" };
  const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${GROQ_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(45000),
  });
  if (!r.ok) { const e = new Error(`Groq ${r.status}: ${(await r.text()).slice(0, 300)}`); e.status = r.status; throw e; }
  return (await r.json()).choices[0].message.content;
}
async function planFromImage(messages) {
  let text;
  try { text = await callGroq(messages, true); }
  catch (e) { if (e.status === 400) text = await callGroq(messages, false); else throw e; }
  try { return parsePlan(text); }
  catch { return parsePlan(await callGroq(messages, false)); }
}

app.post("/api/workout", wrap(async (req, res) => {
  const uid = authUid(req);
  if (!uid) return res.status(401).json({ error: "Please sign in first." });
  const b = req.body || {};
  const level = ["Beginner", "Intermediate", "Advanced"].includes(b.level) ? b.level : "Beginner";
  const goal = GOALS.includes(b.goal) ? b.goal : "Energy";
  const avoid = (Array.isArray(b.avoid) ? b.avoid : []).filter((x) => AVOIDS.includes(x));
  const space = b.space === "Small" ? "Small" : "Normal";
  const recent = (Array.isArray(b.recent) ? b.recent : []).slice(-20).map((x) => String(x).slice(0, 40));
  const image = String(b.image || "");
  if (!/^data:image\/(jpeg|png|webp);base64,/.test(image)) return res.status(400).json({ error: "Send the photo as a JPEG, PNG or WebP data URL." });
  if (image.length > 4_000_000) return res.status(413).json({ error: "Photo is too large. Try a smaller one." });

  const pro = await getPro(req);
  const day = dayOf(tzOf(req));
  const limit = pro ? PRO_LIMIT : FREE_LIMIT;
  if ((await usedToday([`u:${uid}`], day)) >= limit || (await usedToday([`i:${req.ip}`], day)) >= IP_LIMIT) {
    return res.status(429).json({
      error: pro ? "Daily limit reached. Come back tomorrow." : "You have used today’s free workout. Upgrade to Pro for more.",
      upgrade: !pro,
    });
  }

  const userText = `Level: ${level}\nGoal: ${goal}\nSpace: ${space}\nAreas to avoid: ${avoid.join(", ") || "none"}\nRecently done moves (avoid repeating): ${recent.join(", ") || "none"}\nAnalyse the photo and build today's workout.`;
  const messages = [
    { role: "system", content: SYSTEM },
    { role: "user", content: [{ type: "text", text: userText }, { type: "image_url", image_url: { url: image } }] },
  ];

  let plan, aiFailed = false;
  try { plan = await planFromImage(messages); }
  catch (e) {
    console.error("[workout] AI failed:", e.message);
    aiFailed = true;
    plan = { note: "I couldn’t analyse the photo this time, so here is a balanced 15 for today.", focus: "Full body", obs: [], moves: FALLBACK };
  }
  if (plan.retake) return res.json({ retake: true, tip: plan.tip }); // not counted

  await Promise.all([bump(`u:${uid}`, day), bump(`i:${req.ip}`, day)]);
  res.json({ ...plan, pro: !!pro, fallback: aiFailed });
}));

/* ---------- Start ---------- */
const port = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(port, () => console.log(`Listening on ${port}`)))
  .catch((e) => { console.error("DB init failed:", e); process.exit(1); });
