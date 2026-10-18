// מריץ את כל הסריקה על קובץ מקומי (fetch מדומה) ובודק שלכל ממצא יש פתרון מלא
import { readFileSync } from "node:fs";
import { scan } from "../supabase/functions/scan/engine.ts";

const file = process.argv[2] || "bad";
const html = readFileSync(new URL(`./${file}.html`, import.meta.url), "utf8");
globalThis.fetch = async (url) => {
  const u = String(url);
  if (u.includes("dns-query")) {
    const type = new URL(u).searchParams.get("type");
    const ans = { A: [{ type: 1, data: "93.184.216.34" }], AAAA: [], TXT: [], MX: [{ type: 15, data: "1 aspmx.l.google.com." }], NS: [{ type: 2, data: "ns1.wixdns.net." }] }[type] || [];
    return new Response(JSON.stringify({ Status: 0, Answer: ans }), { headers: { "content-type": "application/json" } });
  }
  if (/\/(privacy|policy|מדיניות)/.test(decodeURI(u))) return new Response("nf", { status: 404, headers: { "content-type": "text/html" } });
  return new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
};

const r = await scan("https://example.co.il");
console.log("site:", r.meta.siteName, "| email:", r.meta.contactEmail, "| phone:", r.meta.contactPhone, "| cms:", r.meta.cms, "| mail:", r.meta.mailProvider, "| dns:", r.meta.dnsProvider);
let bad = 0;
for (const f of r.findings) {
  const h = f.howTo;
  const ok = h && h.why && h.steps.length && h.who && h.time;
  if (!ok) bad++;
  console.log(`${ok ? "✓" : "✗"} ${f.id} | steps ${h?.steps.length ?? 0} | copy ${h?.copy?.length ?? 0} | platform ${h?.platform?.name ?? "-"}`);
}
const n = r.findings.find(f => f.id.endsWith("-notice"));
if (n) console.log("\n--- notice ---\n" + n.howTo.copy[0].text);
const p = r.findings.find(f => f.id === "no-privacy-policy");
if (p) console.log("\n--- policy (first 400) ---\n" + p.howTo.copy[0].text.slice(0, 400));
const placeholders = JSON.stringify(r.findings.map(f => f.howTo)).match(/\[[^\]]{2,40}\]/g) || [];
console.log("\nplaceholders:", [...new Set(placeholders)].join(" "));
process.exit(bad ? 1 : 0);
