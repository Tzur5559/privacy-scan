import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { scan } from "./engine.ts";
import { PAGE } from "./page.ts";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" } });

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {});

async function sha(s: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

// הגבלת קצב פשוטה: 10 סריקות לשעה לכתובת IP
async function rateLimited(ipHash: string) {
  const since = new Date(Date.now() - 3600_000).toISOString();
  const { count } = await db.from("pscan_scans").select("id", { count: "exact", head: true }).eq("ip_hash", ipHash).gte("created_at", since);
  return (count ?? 0) >= 10;
}

function validTarget(u: string) {
  try {
    const url = new URL(/^https?:\/\//i.test(u) ? u : "https://" + u);
    const h = url.hostname;
    if (!h.includes(".")) return false;
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.)/.test(h)) return false;
    if (/\.(local|internal|supabase\.co)$/.test(h)) return false;
    return true;
  } catch { return false; }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  let body: { action?: string; url?: string; scan_id?: string; name?: string; email?: string; phone?: string; business?: string; note?: string };
  if (req.method === "GET") {
    const q = new URL(req.url).searchParams.get("url");
    if (!q) return new Response(PAGE, { headers: { ...CORS, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=300" } });
    body = { url: q };
  } else if (req.method === "POST") {
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  } else return json({ error: "GET or POST" }, 405);

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "0";
  const ipHash = await sha(ip + (Deno.env.get("IP_SALT") ?? "s"));

  // --- השארת פרטים ---
  if (body.action === "lead") {
    if (!body.email && !body.phone) return json({ error: "צריך מייל או טלפון" }, 400);
    const { error } = await db.from("pscan_leads").insert({
      scan_id: body.scan_id || null, name: body.name?.slice(0, 120), email: body.email?.slice(0, 200),
      phone: body.phone?.slice(0, 40), business: body.business?.slice(0, 200), note: body.note?.slice(0, 1000),
    });
    if (error) return json({ error: error.message }, 500);
    return json({ ok: true });
  }

  // --- סריקה ---
  const target = (body.url || "").trim();
  if (!target || !validTarget(target)) return json({ error: "כתובת לא תקינה" }, 400);
  if (await rateLimited(ipHash)) return json({ error: "יותר מדי סריקות. נסה שוב בעוד שעה." }, 429);

  const report = await scan(target);
  const { data, error } = await db.from("pscan_scans").insert({
    url: report.url, host: new URL(report.finalUrl).hostname.replace(/^www\./, ""),
    score: report.score, exposure: report.exposure, forms_count: report.meta.formsCount,
    trackers_count: report.meta.trackersCount, cms: report.meta.cms ?? null, report, ip_hash: ipHash,
  }).select("id").single();
  if (error) console.error("insert failed", error.message);

  return json({ scan_id: data?.id ?? null, ...report });
});
