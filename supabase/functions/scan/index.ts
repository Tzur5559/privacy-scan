import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { scan, staticSafe } from "./engine.ts";

// רק הדף שלנו רשאי לשלוח לידים מדפדפן. סריקה פתוחה לכולם (זה המוצר).
const ALLOWED_ORIGINS = ["https://tzur5559.github.io"];
const SCANS_PER_HOUR = 10;
const LEADS_PER_HOUR = 3;
const MAX_BODY = 4_000;

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false, autoRefreshToken: false },
});

function cors(origin: string | null) {
  return {
    "Access-Control-Allow-Origin": origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
  };
}

async function sha(s: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

async function countSince(table: string, ipHash: string, minutes: number) {
  const since = new Date(Date.now() - minutes * 60_000).toISOString();
  const { count } = await db.from(table).select("id", { count: "exact", head: true }).eq("ip_hash", ipHash).gte("created_at", since);
  return count ?? 0;
}

const clean = (v: unknown, max: number) =>
  typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f<>]/g, "").trim().slice(0, max) || null : null;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,24}$/i;
const PHONE = /^[+\d][\d\s\-()]{6,19}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

Deno.serve(async (req) => {
  const origin = req.headers.get("origin");
  const headers = cors(origin);
  const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...headers, "Content-Type": "application/json; charset=utf-8" } });

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });

  let body: Record<string, unknown>;
  if (req.method === "GET") {
    body = { url: new URL(req.url).searchParams.get("url") ?? "" };
  } else if (req.method === "POST") {
    const raw = await req.text();
    if (raw.length > MAX_BODY) return json({ error: "בקשה גדולה מדי" }, 413);
    try { body = JSON.parse(raw); } catch { return json({ error: "בקשה לא תקינה" }, 400); }
    if (!body || typeof body !== "object") return json({ error: "בקשה לא תקינה" }, 400);
  } else return json({ error: "שיטה לא נתמכת" }, 405);

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "0";
  const ipHash = await sha(ip + (Deno.env.get("IP_SALT") ?? "pscan-default-salt"));

  try {
    // ---------- ליד ----------
    if (body.action === "lead") {
      if (!origin || !ALLOWED_ORIGINS.includes(origin)) return json({ error: "לא מורשה" }, 403);
      const email = clean(body.email, 200), phone = clean(body.phone, 30);
      if (email && !EMAIL.test(email)) return json({ error: "כתובת אימייל לא תקינה" }, 400);
      if (phone && !PHONE.test(phone)) return json({ error: "מספר טלפון לא תקין" }, 400);
      if (!email && !phone) return json({ error: "צריך אימייל או טלפון" }, 400);
      if (await countSince("pscan_leads", ipHash, 60) >= LEADS_PER_HOUR) return json({ error: "כבר קיבלנו את הפרטים שלך. נחזור אליך." }, 429);
      const scanId = typeof body.scan_id === "string" && UUID.test(body.scan_id) ? body.scan_id : null;
      const { error } = await db.from("pscan_leads").insert({
        scan_id: scanId, name: clean(body.name, 120), business: clean(body.business, 200),
        phone, email, note: clean(body.note, 1000), ip_hash: ipHash,
      });
      if (error) { console.error("lead insert", error.code); return json({ error: "לא הצלחנו לשמור. נסו שוב." }, 500); }
      return json({ ok: true });
    }

    // ---------- סריקה ----------
    let target = typeof body.url === "string" ? body.url.trim().slice(0, 300) : "";
    if (target && !/^https?:\/\//i.test(target)) target = "https://" + target;
    if (!target || !staticSafe(target)) return json({ error: "כתובת לא תקינה. הכניסו כתובת של אתר, למשל example.co.il" }, 400);
    if (await countSince("pscan_scans", ipHash, 60) >= SCANS_PER_HOUR) return json({ error: "הגעתם למגבלת הבדיקות לשעה. נסו שוב מאוחר יותר." }, 429);

    const report = await scan(target);
    const { data, error } = await db.from("pscan_scans").insert({
      url: report.url.slice(0, 300), host: new URL(report.finalUrl).hostname.replace(/^www\./, ""),
      score: report.score, exposure: report.exposure, forms_count: report.meta.formsCount,
      trackers_count: report.meta.trackersCount, cms: report.meta.cms ?? null, report, ip_hash: ipHash,
    }).select("id").single();
    if (error) console.error("scan insert", error.code);
    return json({ scan_id: data?.id ?? null, ...report });
  } catch (e) {
    console.error("unhandled", (e as Error)?.name);
    return json({ error: "משהו השתבש. נסו שוב בעוד רגע." }, 500);
  }
});
