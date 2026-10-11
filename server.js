require("dotenv").config();
const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false });
const isProd = process.env.NODE_ENV === "production";

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be set to a random value of at least 32 characters.");
  process.exit(1);
}
if (isProd) app.set("trust proxy", 1);
app.use(helmet());
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(session({
  store: new PgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  name: "investpro.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProd, sameSite: "lax", maxAge: 1000 * 60 * 60 * 4 }
}));
app.use(express.static(path.join(__dirname, "public")));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false });

function requireAdmin(req, res, next) {
  if (!req.session.admin) return res.status(401).json({ error: "অনুগ্রহ করে অ্যাডমিন হিসেবে লগইন করুন।" });
  next();
}
async function audit(admin, action, type, id, details = {}) {
  await pool.query("INSERT INTO admin_audit_log(admin_email,action,target_type,target_id,details) VALUES($1,$2,$3,$4,$5)", [admin, action, type, id == null ? null : String(id), JSON.stringify(details)]);
}
app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password || !process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) return res.status(400).json({ error: "অ্যাডমিন লগইন কনফিগার করা নেই।" });
    const matches = String(email).trim().toLowerCase() === process.env.ADMIN_EMAIL.trim().toLowerCase()
      && await bcrypt.compare(String(password), await bcrypt.hash(process.env.ADMIN_PASSWORD, 12));
    if (!matches) return res.status(401).json({ error: "ইমেইল বা পাসওয়ার্ড সঠিক নয়।" });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "সেশন তৈরি করা যায়নি।" });
      req.session.admin = { email: process.env.ADMIN_EMAIL };
      res.json({ ok: true, email: process.env.ADMIN_EMAIL });
    });
  } catch (e) { console.error(e); res.status(500).json({ error: "সার্ভার সমস্যা হয়েছে।" }); }
});
app.post("/api/logout", (req, res) => req.session.destroy(() => { res.clearCookie("investpro.sid"); res.json({ ok: true }); }));
app.get("/api/me", (req, res) => res.json({ admin: req.session.admin || null }));

app.get("/api/overview", requireAdmin, async (req, res) => {
  try {
    const [users, pendingDeposits, pendingWithdrawals, balances, recent] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE status='active')::int AS active, COUNT(*) FILTER (WHERE status='suspended')::int AS suspended FROM users"),
      pool.query("SELECT COUNT(*)::int AS count, COALESCE(SUM(amount),0)::text AS amount FROM deposits WHERE status='pending'"),
      pool.query("SELECT COUNT(*)::int AS count, COALESCE(SUM(amount),0)::text AS amount FROM withdrawals WHERE status='pending'"),
      pool.query("SELECT COALESCE(SUM(balance),0)::text AS amount FROM wallets"),
      pool.query("SELECT t.id,t.user_id,u.full_name,t.kind,t.amount::text,t.note,t.created_at FROM transactions t JOIN users u ON u.id=t.user_id ORDER BY t.created_at DESC LIMIT 8")
    ]);
    res.json({ users: users.rows[0], pendingDeposits: pendingDeposits.rows[0], pendingWithdrawals: pendingWithdrawals.rows[0], balances: balances.rows[0], recent: recent.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "ডাটাবেসে সমস্যা হয়েছে। schema.sql চালানো হয়েছে কি না দেখুন।" }); }
});

app.get("/api/users", requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || "").trim().slice(0,100);
    const status = ["active","suspended","closed"].includes(req.query.status) ? req.query.status : null;
    const result = await pool.query(
      `SELECT u.id,u.full_name,u.email,u.phone,u.status,u.created_at,COALESCE(w.balance,0)::text AS balance
       FROM users u LEFT JOIN wallets w ON w.user_id=u.id
       WHERE ($1='' OR u.full_name ILIKE '%'||$1||'%' OR u.email ILIKE '%'||$1||'%' OR COALESCE(u.phone,'') ILIKE '%'||$1||'%' OR u.id::text=$1)
       AND ($2::text IS NULL OR u.status=$2) ORDER BY u.created_at DESC LIMIT 300`, [q,status]);
    res.json(result.rows);
  } catch(e) { console.error(e); res.status(500).json({error:"ইউজার লোড করা যায়নি।"}); }
});
app.patch("/api/users/:id/status", requireAdmin, async (req,res) => {
  const status = req.body.status;
  if (!["active","suspended","closed"].includes(status)) return res.status(400).json({error:"স্ট্যাটাস সঠিক নয়।"});
  try {
    const r = await pool.query("UPDATE users SET status=$1 WHERE id=$2 RETURNING id,status", [status, req.params.id]);
    if (!r.rowCount) return res.status(404).json({error:"ইউজার পাওয়া যায়নি।"});
    await audit(req.session.admin.email,"user_status_changed","user",req.params.id,{status});
    res.json({ok:true,user:r.rows[0]});
  } catch(e) { console.error(e); res.status(500).json({error:"স্ট্যাটাস পরিবর্তন করা যায়নি।"}); }
});
app.get("/api/deposits", requireAdmin, async (req,res) => {
  try {
    const status = ["pending","approved","rejected"].includes(req.query.status) ? req.query.status : null;
    const r = await pool.query(`SELECT d.*,u.full_name,u.email FROM deposits d JOIN users u ON u.id=d.user_id WHERE ($1::text IS NULL OR d.status=$1) ORDER BY d.requested_at DESC LIMIT 300`,[status]);
    res.json(r.rows);
  } catch(e) { console.error(e); res.status(500).json({error:"ডিপোজিট লোড করা যায়নি।"}); }
});
app.post("/api/deposits/:id/review", requireAdmin, async (req,res) => {
  const decision = req.body.decision;
  if (!["approved","rejected"].includes(decision)) return res.status(400).json({error:"সিদ্ধান্ত সঠিক নয়।"});
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const d = await client.query("SELECT * FROM deposits WHERE id=$1 FOR UPDATE",[req.params.id]);
    if (!d.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({error:"ডিপোজিট পাওয়া যায়নি।"}); }
    const row = d.rows[0];
    if (row.status !== "pending") { await client.query("ROLLBACK"); return res.status(409).json({error:"এই অনুরোধ আগে পর্যালোচনা করা হয়েছে।"}); }
    await client.query("UPDATE deposits SET status=$1,reviewed_at=NOW(),reviewed_by=$2,review_note=$3 WHERE id=$4",[decision,req.session.admin.email,String(req.body.note||"").slice(0,500),row.id]);
    if (decision === "approved") {
      await client.query("INSERT INTO wallets(user_id,balance) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET balance=wallets.balance+EXCLUDED.balance,updated_at=NOW()",[row.user_id,row.amount]);
      await client.query("INSERT INTO transactions(user_id,kind,amount,reference_type,reference_id,note) VALUES($1,'deposit',$2,'deposit',$3,'Admin-approved deposit')",[row.user_id,row.amount,row.id]);
    }
    await client.query("INSERT INTO admin_audit_log(admin_email,action,target_type,target_id,details) VALUES($1,$2,'deposit',$3,$4)",[req.session.admin.email,"deposit_"+decision,String(row.id),JSON.stringify({amount:row.amount.toString(),user_id:row.user_id})]);
    await client.query("COMMIT");
    res.json({ok:true});
  } catch(e) { await client.query("ROLLBACK"); console.error(e); res.status(500).json({error:"ডিপোজিট রিভিউ করা যায়নি।"}); }
  finally { client.release(); }
});
app.get("/api/withdrawals", requireAdmin, async (req,res) => {
  try {
    const status = ["pending","approved","rejected","paid"].includes(req.query.status) ? req.query.status : null;
    const r = await pool.query(`SELECT w.*,u.full_name,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE ($1::text IS NULL OR w.status=$1) ORDER BY w.requested_at DESC LIMIT 300`,[status]);
    res.json(r.rows);
  } catch(e) { console.error(e); res.status(500).json({error:"উইথড্র লোড করা যায়নি।"}); }
});
app.post("/api/withdrawals/:id/review", requireAdmin, async (req,res) => {
  const decision = req.body.decision;
  if (!["approved","rejected","paid"].includes(decision)) return res.status(400).json({error:"সিদ্ধান্ত সঠিক নয়।"});
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const wr = await client.query("SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE",[req.params.id]);
    if (!wr.rowCount) { await client.query("ROLLBACK"); return res.status(404).json({error:"উইথড্র পাওয়া যায়নি।"}); }
    const w = wr.rows[0];
    if (decision === "paid" && w.status !== "approved") { await client.query("ROLLBACK"); return res.status(409).json({error:"শুধু অনুমোদিত উইথড্রকে Paid করা যাবে।"}); }
    if (decision !== "paid" && w.status !== "pending") { await client.query("ROLLBACK"); return res.status(409).json({error:"এই অনুরোধ আগে পর্যালোচনা করা হয়েছে।"}); }
    if (decision === "approved") {
      const wallet = await client.query("SELECT balance FROM wallets WHERE user_id=$1 FOR UPDATE",[w.user_id]);
      if (!wallet.rowCount || Number(wallet.rows[0].balance) < Number(w.amount)) { await client.query("ROLLBACK"); return res.status(409).json({error:"ইউজারের ব্যালেন্স পর্যাপ্ত নয়।"}); }
      await client.query("UPDATE wallets SET balance=balance-$1,updated_at=NOW() WHERE user_id=$2",[w.amount,w.user_id]);
      await client.query("INSERT INTO transactions(user_id,kind,amount,reference_type,reference_id,note) VALUES($1,'withdrawal',$2,'withdrawal',$3,'Withdrawal approved; funds reserved')",[w.user_id,(-Number(w.amount)).toFixed(2),w.id]);
    }
    await client.query("UPDATE withdrawals SET status=$1,reviewed_at=NOW(),reviewed_by=$2,review_note=$3 WHERE id=$4",[decision,req.session.admin.email,String(req.body.note||"").slice(0,500),w.id]);
    await client.query("INSERT INTO admin_audit_log(admin_email,action,target_type,target_id,details) VALUES($1,$2,'withdrawal',$3,$4)",[req.session.admin.email,"withdrawal_"+decision,String(w.id),JSON.stringify({amount:w.amount.toString(),user_id:w.user_id})]);
    await client.query("COMMIT");
    res.json({ok:true});
  } catch(e) { await client.query("ROLLBACK"); console.error(e); res.status(500).json({error:"উইথড্র রিভিউ করা যায়নি।"}); }
  finally { client.release(); }
});
app.get("/api/transactions", requireAdmin, async (req,res) => {
  try {
    const userId = String(req.query.user_id||"").trim();
    const r = await pool.query(`SELECT t.*,u.full_name,u.email FROM transactions t JOIN users u ON u.id=t.user_id WHERE ($1='' OR t.user_id::text=$1) ORDER BY t.created_at DESC LIMIT 500`,[userId]);
    res.json(r.rows);
  } catch(e) { console.error(e); res.status(500).json({error:"লেনদেন লোড করা যায়নি।"}); }
});
app.get("/api/audit", requireAdmin, async (req,res) => {
  try { const r = await pool.query("SELECT * FROM admin_audit_log ORDER BY created_at DESC LIMIT 300"); res.json(r.rows); }
  catch(e) { console.error(e); res.status(500).json({error:"অডিট লগ লোড করা যায়নি।"}); }
});
app.get("/api/export/users.csv", requireAdmin, async (req,res) => {
  try {
    const r = await pool.query("SELECT u.id,u.full_name,u.email,u.phone,u.status,u.created_at,COALESCE(w.balance,0)::text AS balance FROM users u LEFT JOIN wallets w ON w.user_id=u.id ORDER BY u.id");
    const cell = v => `"${String(v ?? "").replace(/"/g,'""')}"`;
    const csv = ["id,full_name,email,phone,status,created_at,balance", ...r.rows.map(x => [x.id,x.full_name,x.email,x.phone,x.status,x.created_at.toISOString(),x.balance].map(cell).join(","))].join("\r\n");
    res.setHeader("Content-Type","text/csv; charset=utf-8"); res.setHeader("Content-Disposition",'attachment; filename="investpro-users.csv"'); res.send("\uFEFF"+csv);
  } catch(e) { console.error(e); res.status(500).send("Export failed"); }
});

app.get("*", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`InvestPro admin running on port ${port}`));
