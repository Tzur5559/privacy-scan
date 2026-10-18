// מסך ניהול: כניסה בקוד חד-פעמי למייל, ניהול לידים, סריקות והגדרות.
import type { SupabaseClient } from "jsr:@supabase/supabase-js@2";
import { esc, mailConfigured, mailProvider, sendMail, wrap } from "./mail.ts";

export const ADMIN_URL = "https://tzur5559.github.io/privacy-scan/admin.html";
const CODE_TTL_MIN = 10;
const SESSION_HOURS = 12;
const MAX_ATTEMPTS = 5;
const CODES_PER_IP_HOUR = 6;
const CODES_PER_EMAIL_15MIN = 3;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,24}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STATUSES = ["new", "contacted", "customer", "not_relevant"];

type Json = Record<string, unknown>;
type Out = { status: number; body: Json };
const ok = (body: Json): Out => ({ status: 200, body });
const err = (status: number, error: string): Out => ({ status, body: { error } });

async function sha(s: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}
const salt = () => Deno.env.get("IP_SALT") ?? "pscan-default-salt";
const normEmail = (v: unknown) => (typeof v === "string" ? v.trim().toLowerCase().slice(0, 254) : "");

function randomCode() {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return String(a[0] % 1_000_000).padStart(6, "0");
}
function randomToken() {
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  return [...a].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function getSettings(db: SupabaseClient) {
  const { data } = await db.from("pscan_settings").select("*").eq("id", true).single();
  return data as {
    notify_enabled: boolean; notify_emails: string[]; admin_emails: string[];
    sender_email: string | null; sender_name: string; updated_at: string; updated_by: string | null;
  } | null;
}

// ---------- התראה על ליד חדש ----------
export async function notifyLead(db: SupabaseClient, lead: Json, scanId: string | null) {
  try {
    const s = await getSettings(db);
    if (!s || !s.notify_enabled || !s.notify_emails?.length || !s.sender_email) return;
    let scanLine = "";
    if (scanId) {
      const { data } = await db.from("pscan_scans").select("url,score,exposure").eq("id", scanId).single();
      if (data) scanLine = `<p><b>האתר שנסרק:</b> ${esc(data.url)}<br><b>ציון:</b> ${esc(data.score)}/100</p>`;
    }
    const rows = [["שם", lead.name], ["עסק", lead.business], ["טלפון", lead.phone], ["אימייל", lead.email], ["הערה", lead.note]]
      .filter(([, v]) => v)
      .map(([k, v]) => `<tr><td style="padding:4px 0 4px 12px;color:#6b6f8a">${k}</td><td style="padding:4px 0"><b>${esc(v)}</b></td></tr>`)
      .join("");
    const html = wrap("ליד חדש מהסורק", `<table style="border-collapse:collapse">${rows}</table>${scanLine}
<p><a href="${ADMIN_URL}" style="display:inline-block;background:#4338ca;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">לפתיחת מסך הניהול</a></p>`);
    const text = `ליד חדש מהסורק\n${[["שם", lead.name], ["עסק", lead.business], ["טלפון", lead.phone], ["אימייל", lead.email]].filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`).join("\n")}\n${ADMIN_URL}`;
    await sendMail({
      to: s.notify_emails, subject: `ליד חדש: ${String(lead.name || lead.business || lead.email || lead.phone || "").slice(0, 60)}`,
      html, text, senderEmail: s.sender_email, senderName: s.sender_name,
      replyTo: typeof lead.email === "string" ? lead.email : undefined,
    });
  } catch (e) {
    console.error("notify", (e as Error)?.name);
  }
}

// ---------- אימות סשן ----------
async function session(db: SupabaseClient, req: Request) {
  const auth = req.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!/^[0-9a-f]{64}$/.test(token)) return null;
  const { data } = await db.from("pscan_admin_sessions").select("email,expires_at").eq("token_hash", await sha(token)).maybeSingle();
  if (!data || new Date(data.expires_at) < new Date()) return null;
  const s = await getSettings(db);
  if (!s?.admin_emails?.map(e => e.toLowerCase()).includes(data.email)) return null; // הוסר מרשימת המנהלים
  return { email: data.email as string, tokenHash: await sha(token) };
}

// ---------- נקודת כניסה ----------
export async function handleAdmin(db: SupabaseClient, req: Request, body: Json, ipHash: string): Promise<Out> {
  const action = String(body.action);

  // שלב 1: בקשת קוד. התשובה זהה תמיד, כדי לא לחשוף אילו כתובות הן של מנהלים.
  if (action === "admin_request_code") {
    const email = normEmail(body.email);
    const generic = ok({ ok: true, message: "אם הכתובת מורשית, נשלח אליה קוד כניסה." });
    if (!EMAIL.test(email)) return err(400, "כתובת אימייל לא תקינה");
    const hourAgo = new Date(Date.now() - 3_600_000).toISOString();
    const q15 = new Date(Date.now() - 900_000).toISOString();
    const { count: byIp } = await db.from("pscan_admin_codes").select("id", { count: "exact", head: true }).eq("ip_hash", ipHash).gte("created_at", hourAgo);
    if ((byIp ?? 0) >= CODES_PER_IP_HOUR) return err(429, "יותר מדי ניסיונות. נסו שוב בעוד שעה.");
    const s = await getSettings(db);
    const allowed = s?.admin_emails?.map(e => e.toLowerCase()).includes(email);
    if (!allowed) {
      await db.from("pscan_admin_codes").insert({ email, code_hash: "-", expires_at: new Date().toISOString(), used: true, ip_hash: ipHash });
      return generic;
    }
    const { count: byEmail } = await db.from("pscan_admin_codes").select("id", { count: "exact", head: true }).eq("email", email).gte("created_at", q15);
    if ((byEmail ?? 0) >= CODES_PER_EMAIL_15MIN) return generic;
    if (!mailConfigured() || !s?.sender_email) return err(503, "שליחת מיילים עוד לא הוגדרה במערכת.");
    const code = randomCode();
    await db.from("pscan_admin_codes").update({ used: true }).eq("email", email).eq("used", false);
    await db.from("pscan_admin_codes").insert({
      email, code_hash: await sha(code + email + salt()), ip_hash: ipHash,
      expires_at: new Date(Date.now() + CODE_TTL_MIN * 60_000).toISOString(),
    });
    const sent = await sendMail({
      to: [email], subject: `קוד הכניסה שלך: ${code}`,
      html: wrap("קוד כניסה למסך הניהול", `<p>הקוד שלך:</p><p style="font-size:30px;font-weight:bold;letter-spacing:6px;direction:ltr;text-align:center">${code}</p><p>הקוד בתוקף ${CODE_TTL_MIN} דקות. אם לא ביקשת להיכנס, אפשר להתעלם מהמייל הזה.</p>`),
      text: `קוד הכניסה שלך: ${code}\nבתוקף ${CODE_TTL_MIN} דקות.`,
      senderEmail: s.sender_email, senderName: s.sender_name,
    });
    if (!sent.ok) return err(502, "שליחת המייל נכשלה. בדקו את הגדרות שליחת המיילים.");
    return generic;
  }

  // שלב 2: אימות קוד → סשן
  if (action === "admin_verify") {
    const email = normEmail(body.email);
    const code = typeof body.code === "string" ? body.code.replace(/\D/g, "") : "";
    if (!EMAIL.test(email) || code.length !== 6) return err(400, "קוד לא תקין");
    const { data: row } = await db.from("pscan_admin_codes").select("id,code_hash,expires_at,attempts")
      .eq("email", email).eq("used", false).order("created_at", { ascending: false }).limit(1).maybeSingle();
    if (!row || new Date(row.expires_at) < new Date() || row.attempts >= MAX_ATTEMPTS) return err(401, "הקוד שגוי או שפג תוקפו. בקשו קוד חדש.");
    if (row.code_hash !== await sha(code + email + salt())) {
      const attempts = row.attempts + 1;
      await db.from("pscan_admin_codes").update({ attempts, used: attempts >= MAX_ATTEMPTS }).eq("id", row.id);
      return err(401, "הקוד שגוי או שפג תוקפו. בקשו קוד חדש.");
    }
    await db.from("pscan_admin_codes").update({ used: true }).eq("id", row.id);
    const s = await getSettings(db);
    if (!s?.admin_emails?.map(e => e.toLowerCase()).includes(email)) return err(401, "אין הרשאה");
    const token = randomToken();
    await db.from("pscan_admin_sessions").delete().lt("expires_at", new Date().toISOString());
    await db.from("pscan_admin_sessions").insert({
      token_hash: await sha(token), email, expires_at: new Date(Date.now() + SESSION_HOURS * 3_600_000).toISOString(),
    });
    return ok({ token, email, expires_in_hours: SESSION_HOURS });
  }

  // מכאן והלאה — רק עם סשן תקף
  const me = await session(db, req);
  if (!me) return err(401, "צריך להתחבר מחדש");

  switch (action) {
    case "admin_logout": {
      await db.from("pscan_admin_sessions").delete().eq("token_hash", me.tokenHash);
      return ok({ ok: true });
    }
    case "admin_overview": {
      const week = new Date(Date.now() - 7 * 86_400_000).toISOString();
      const c = async (t: string, f?: (q: any) => any) => {
        let q = db.from(t).select("id", { count: "exact", head: true });
        if (f) q = f(q);
        return (await q).count ?? 0;
      };
      const [scans, scansWeek, leads, leadsNew] = await Promise.all([
        c("pscan_scans"), c("pscan_scans", q => q.gte("created_at", week)),
        c("pscan_leads"), c("pscan_leads", q => q.eq("status", "new")),
      ]);
      return ok({ me: me.email, scans, scansWeek, leads, leadsNew, mailConfigured: mailConfigured(), provider: mailProvider() });
    }
    case "admin_leads": {
      let q = db.from("pscan_leads").select("id,created_at,name,business,phone,email,note,status,admin_note,scan_id,pscan_scans(url,score)")
        .order("created_at", { ascending: false }).limit(500);
      if (typeof body.status === "string" && STATUSES.includes(body.status)) q = q.eq("status", body.status);
      const { data, error } = await q;
      if (error) { console.error("leads", error.code); return err(500, "שגיאה בטעינת לידים"); }
      return ok({ leads: data });
    }
    case "admin_lead_update": {
      if (typeof body.id !== "string" || !UUID.test(body.id)) return err(400, "מזהה לא תקין");
      const patch: Json = { updated_at: new Date().toISOString() };
      if (typeof body.status === "string") {
        if (!STATUSES.includes(body.status)) return err(400, "סטטוס לא תקין");
        patch.status = body.status;
      }
      if (typeof body.admin_note === "string") patch.admin_note = body.admin_note.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "").slice(0, 2000);
      const { error } = await db.from("pscan_leads").update(patch).eq("id", body.id);
      if (error) { console.error("lead upd", error.code); return err(500, "השמירה נכשלה"); }
      return ok({ ok: true });
    }
    case "admin_lead_delete": {
      if (typeof body.id !== "string" || !UUID.test(body.id)) return err(400, "מזהה לא תקין");
      const { error } = await db.from("pscan_leads").delete().eq("id", body.id);
      if (error) { console.error("lead del", error.code); return err(500, "המחיקה נכשלה"); }
      return ok({ ok: true });
    }
    case "admin_scans": {
      let q = db.from("pscan_scans").select("id,created_at,url,host,score,exposure,forms_count,trackers_count,cms")
        .order("created_at", { ascending: false }).limit(500);
      const term = typeof body.q === "string" ? body.q.trim().toLowerCase().replace(/[^a-z0-9.\-֐-׿]/g, "").slice(0, 100) : "";
      if (term) q = q.ilike("host", `%${term}%`);
      const { data, error } = await q;
      if (error) { console.error("scans", error.code); return err(500, "שגיאה בטעינת סריקות"); }
      return ok({ scans: data });
    }
    case "admin_scan_get": {
      if (typeof body.id !== "string" || !UUID.test(body.id)) return err(400, "מזהה לא תקין");
      const { data } = await db.from("pscan_scans").select("id,created_at,url,report").eq("id", body.id).maybeSingle();
      if (!data) return err(404, "לא נמצא");
      return ok({ scan: data });
    }
    case "admin_settings_get": {
      const s = await getSettings(db);
      return ok({ settings: s, mailConfigured: mailConfigured(), provider: mailProvider() });
    }
    case "admin_settings_save": {
      const list = (v: unknown) => Array.isArray(v)
        ? [...new Set(v.map(normEmail).filter(Boolean))].slice(0, 10)
        : null;
      const notify = list(body.notify_emails), admins = list(body.admin_emails);
      if (!notify || !admins) return err(400, "נתונים לא תקינים");
      const bad = [...notify, ...admins].find(e => !EMAIL.test(e));
      if (bad) return err(400, `כתובת לא תקינה: ${bad}`);
      if (!admins.length) return err(400, "חייב להישאר לפחות מנהל אחד");
      if (!admins.includes(me.email)) return err(400, "אי אפשר להסיר את עצמך מרשימת המנהלים מכאן");
      const sender = normEmail(body.sender_email);
      if (!EMAIL.test(sender)) return err(400, "כתובת השולח לא תקינה");
      const senderName = typeof body.sender_name === "string" ? body.sender_name.replace(/[\u0000-\u001f\u007f<>]/g, "").trim().slice(0, 60) : "";
      const { error } = await db.from("pscan_settings").update({
        notify_enabled: body.notify_enabled === true, notify_emails: notify, admin_emails: admins,
        sender_email: sender, sender_name: senderName || "פרטיות בטוח",
        updated_at: new Date().toISOString(), updated_by: me.email,
      }).eq("id", true);
      if (error) { console.error("settings", error.code); return err(500, "השמירה נכשלה"); }
      return ok({ ok: true });
    }
    case "admin_test_email": {
      const s = await getSettings(db);
      if (!s?.notify_emails?.length || !s.sender_email) return err(400, "אין כתובות להתראה");
      const r = await sendMail({
        to: s.notify_emails, subject: "בדיקה: התראות הלידים עובדות",
        html: wrap("בדיקת התראות", "<p>אם קיבלת את המייל הזה, התראות על לידים חדשים יגיעו לכתובת הזאת.</p>"),
        text: "בדיקת התראות: אם קיבלת את המייל הזה, התראות על לידים יגיעו לכאן.",
        senderEmail: s.sender_email, senderName: s.sender_name,
      });
      return r.ok ? ok({ ok: true }) : err(502, "השליחה נכשלה. בדקו שכתובת השולח אומתה אצל ספק המיילים.");
    }
  }
  return err(400, "פעולה לא מוכרת");
}
