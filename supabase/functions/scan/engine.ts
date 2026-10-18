// מנוע סריקה פסיבי — תיקון 13 לחוק הגנת הפרטיות
// רץ על Deno (Supabase Edge) ועל Node 22 (בדיקות). רק web APIs.
import { addHowTo } from "./fixes.ts";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface HowTo {
  why: string;                                   // למה זה חשוב, בשפה פשוטה
  steps: string[];                               // מה לעשות, צעד אחרי צעד
  copy?: { label: string; text: string; ltr?: boolean }[];   // נוסח מוכן להעתקה
  platform?: { name: string; steps: string[] };  // הוראות לפי הפלטפורמה שזוהתה
  who: string;                                   // מי יכול לבצע
  time: string;                                  // כמה זמן זה לוקח
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;        // עברית, קצר
  detail: string;       // עברית, מה נמצא
  law: string;          // הבסיס המשפטי
  fix: string;          // מה לעשות (שורה אחת)
  evidence?: string;    // קטע/URL
  howTo?: HowTo;        // הפתרון המלא
}

export interface FormInfo {
  index: number;
  action: string;
  fieldNames: string[];
  sensitiveFields: string[];
  hasNoticeNearby: boolean;
  noticeHits: string[];   // אילו מתוך 5 פרטי היידוע נמצאו ליד הטופס
  hasConsentCheckbox: boolean;
  consentPrechecked: boolean;
  hasPrivacyLink: boolean;
}

export interface ScanReport {
  url: string;
  finalUrl: string;
  scannedAt: string;
  score: number;            // 0–100, גבוה = טוב
  exposure: "נמוכה" | "בינונית" | "גבוהה";
  summary: string;
  forms: FormInfo[];
  trackers: string[];
  privacyPolicy: { found: boolean; url?: string; hits: string[]; oldTerms: boolean };
  https: { ok: boolean; redirectsHttp?: boolean };
  dns: { spf: boolean; dmarc: boolean };
  headers: Record<string, boolean>;
  findings: Finding[];
  // סטטיסטיקה פנימית + נתונים להתאמת הפתרונות
  meta: {
    formsCount: number; trackersCount: number; cms?: string;
    siteName?: string; contactEmail?: string; contactPhone?: string;
    mailProvider?: string; dnsProvider?: string; host?: string;
  };
}

// ---------- מילונים ----------

const TRACKERS: Array<[RegExp, string]> = [
  [/connect\.facebook\.net|fbq\(|facebook\.com\/tr/i, "Meta Pixel"],
  [/googletagmanager\.com|gtag\(|GTM-[A-Z0-9]+/i, "Google Tag Manager / gtag"],
  [/google-analytics\.com|UA-\d{4,}|G-[A-Z0-9]{6,}/i, "Google Analytics"],
  [/analytics\.tiktok\.com|ttq\.load/i, "TikTok Pixel"],
  [/hotjar\.com|hj\(/i, "Hotjar"],
  [/clarity\.ms/i, "Microsoft Clarity"],
  [/snap\.licdn\.com|linkedin\.com\/px/i, "LinkedIn Insight"],
  [/static\.ads-twitter\.com/i, "X/Twitter Pixel"],
  [/taboola\.com/i, "Taboola"],
  [/outbrain\.com/i, "Outbrain"],
  [/hubspot\.com|hs-scripts/i, "HubSpot"],
  [/intercom\.io|intercomcdn/i, "Intercom"],
  [/tawk\.to/i, "Tawk.to chat"],
  [/crisp\.chat/i, "Crisp chat"],
  [/recaptcha|gstatic\.com\/recaptcha/i, "Google reCAPTCHA"],
  [/elfsight|powr\.io/i, "Widget חיצוני"],
];

// 5 פרטי חובת היידוע — סעיף 11 (אחרי תיקון 13)
const NOTICE_PATTERNS: Array<[RegExp, string]> = [
  [/(חובה|רשות|אינך חייב|אין חובה|לא חלה.*חובה|מרצונ|מרצון|תלוי.*בהסכמ|ללא מסירת|אי.?הסכמה)/, "חובה/רשות ותוצאת אי-הסכמה"],
  [/(מטרת|למטרה|למטרות|לצורך|לשם)/, "מטרת האיסוף"],
  [/(יימסר|יועבר|צד שלישי|צדדים שלישיים|לא נעביר|לא יועבר|ספקי)/, "למי יימסר המידע"],
  [/(בעל השליטה|בעל המאגר|ח\.?פ\.?|ע\.?מ\.?|צור קשר|ליצירת קשר|דוא"ל|טלפון|@)/, "זהות בעל השליטה ודרכי התקשרות"],
  [/(זכות עיון|לעיין במידע|זכות.*תיקון|לתקן את המידע|סעיף 13|סעיף 14|למחוק|מחיקת)/, "זכות עיון ותיקון"],
];

const PRIVACY_LINK = /(מדיניות\s*פרטיות|הצהרת\s*פרטיות|privacy)/i;
const OLD_TERMS = /בעל\s+(ה)?מאגר(?!.*שליטה)/;   // מונח ישן = מדיניות לא עודכנה

// שדות רגישים בטופס — דגל אדום (העיצום מאוגוסט 2026)
const SENSITIVE_FIELDS: Array<[RegExp, string]> = [
  [/(ת\.?ז|תעודת\s*זהות|מספר\s*זהות|\bid_?num|national_?id|israeli_?id|\btz\b)/i, "תעודת זהות"],
  [/(תאריך\s*לידה|birth|dob|גיל\b|\bage\b)/i, "תאריך לידה / גיל"],
  [/(ילד|children|kids|בן\/בת|קטין)/i, "פרטי ילדים"],
  [/(רפואי|בריאות|מחלה|תרופ|health|medical|diagnos|אלרגי)/i, "מידע בריאותי"],
  [/(הכנסה|שכר|משכורת|income|salary|אשראי|credit|חובות|הלוואה)/i, "מידע פיננסי/שכר"],
  [/((^|[\s|])דת([\s|]|$)|מוצא|לאום|religion|ethnic|פוליטי)/i, "דת/מוצא/דעות"],
  [/(סיסמ|password)/i, "סיסמה"],
];

const CMS_HINTS: Array<[RegExp, string]> = [
  [/elementor/i, "WordPress + Elementor"],
  [/wp-content|wp-includes|wordpress/i, "WordPress"],
  [/wixstatic|wix\.com|_wix/i, "Wix"],
  [/cdn\.shopify|shopify/i, "Shopify"],
  [/squarespace/i, "Squarespace"],
  [/webflow/i, "Webflow"],
  [/lovable|gpteng|supabase\.co/i, "Lovable / Supabase"],
];

// ---------- עזרים ----------

function strip(html: string): string {
  return html.replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ");
}

function attr(tag: string, name: string): string {
  const m = tag.match(new RegExp(`${name}\\s*=\\s*["']([^"']*)["']`, "i"));
  return m ? m[1] : "";
}

function hostOf(u: string): string {
  try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return ""; }
}

// ---------- הגנה מ-SSRF: הסורק לעולם לא פונה לכתובות פנימיות ----------

const MAX_BYTES = 2_000_000;   // לא קוראים יותר מ-2MB מעמוד
const MAX_REDIRECTS = 5;

function isPrivateIPv4(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
    (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
}
function isPrivateIPv6(ip: string): boolean {
  const s = ip.toLowerCase();
  if (s === "::" || s === "::1") return true;
  if (s.startsWith("::ffff:")) return isPrivateIPv4(s.slice(7));
  return /^(fc|fd|fe8|fe9|fea|feb|ff)/.test(s);
}

// בדיקה סטטית של כתובת: רק http/https, פורט רגיל, שם דומיין אמיתי (לא IP)
export function staticSafe(raw: string): URL | null {
  let u: URL;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  if (u.username || u.password) return null;
  if (u.port && u.port !== "80" && u.port !== "443") return null;
  const h = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!h.includes(".") || h.length > 253) return null;
  if (/^[\d.]+$/.test(h) || h.includes(":") || h.startsWith("[")) return null;      // IP ישיר אסור
  if (/^0x|^\d+$/.test(h)) return null;
  if (/(^|\.)(localhost|local|internal|intranet|lan|home|corp|arpa)$/.test(h)) return null;
  if (/(^|\.)supabase\.(co|in|com)$/.test(h)) return null;                         // לא סורקים את התשתית שלנו
  return u;
}

// בדיקה דינמית: הדומיין חייב להצביע רק לכתובות ציבוריות (נגד DNS שמפנה פנימה)
async function dohAddrs(host: string, type: "A" | "AAAA"): Promise<string[]> {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, { headers: { accept: "application/dns-json" } });
  if (!r.ok) throw new Error("doh");
  const j = await r.json();
  // type 1 = A, type 28 = AAAA (מדלגים על CNAME שבדרך)
  return (j.Answer || []).filter((a: { type: number }) => a.type === 1 || a.type === 28).map((a: { data: string }) => String(a.data));
}
async function resolvesPublic(host: string): Promise<boolean> {
  try {
    const [a, aaaa] = await Promise.all([dohAddrs(host, "A"), dohAddrs(host, "AAAA").catch(() => [] as string[])]);
    const addrs = [...a, ...aaaa];
    if (!addrs.length) return false;
    return addrs.every(x => x.includes(":") ? !isPrivateIPv6(x) : !isPrivateIPv4(x));
  } catch { return false; }                        // אם לא הצלחנו לבדוק, לא סורקים
}

async function readCapped(r: Response): Promise<string> {
  if (!r.body) return "";
  const reader = r.body.getReader();
  const chunks: Uint8Array[] = []; let n = 0;
  while (n < MAX_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value); n += value.length;
  }
  try { await reader.cancel(); } catch { /* */ }
  const buf = new Uint8Array(Math.min(n, MAX_BYTES)); let o = 0;
  for (const c of chunks) { const take = Math.min(c.length, buf.length - o); buf.set(c.subarray(0, take), o); o += take; if (o >= buf.length) break; }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

async function fetchText(url: string, timeoutMs = 12000): Promise<{ ok: boolean; status: number; text: string; finalUrl: string; headers: Headers }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  const fail = (status = 0) => ({ ok: false, status, text: "", finalUrl: url, headers: new Headers() });
  try {
    let current = url;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const u = staticSafe(current);
      if (!u || !(await resolvesPublic(u.hostname))) return fail(403);
      const r = await fetch(u.toString(), {
        redirect: "manual",                         // כל הפניה נבדקת מחדש
        signal: ctrl.signal,
        headers: { "User-Agent": "Mozilla/5.0 (compatible; PrivacyScanIL/0.2; passive compliance check)", "Accept": "text/html,*/*", "Accept-Language": "he-IL,he;q=0.9,en;q=0.5" },
      });
      if (r.status >= 300 && r.status < 400) {
        const loc = r.headers.get("location");
        try { await r.body?.cancel(); } catch { /* */ }
        if (!loc) return fail(r.status);
        current = new URL(loc, u).toString();
        continue;
      }
      const ctype = r.headers.get("content-type") || "";
      const text = r.ok && /html|text|xml/i.test(ctype || "text/html") ? await readCapped(r) : "";
      if (!text) { try { await r.body?.cancel(); } catch { /* */ } }
      return { ok: r.ok && !!text, status: r.status, text, finalUrl: u.toString(), headers: r.headers };
    }
    return fail(310);
  } catch {
    return fail();
  } finally { clearTimeout(t); }
}

async function dnsTxt(name: string): Promise<string[]> {
  // DNS-over-HTTPS — עובד גם ב-Deno וגם ב-Node, בלי ספריות
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`, {
      headers: { accept: "application/dns-json" },
    });
    if (!r.ok) return [];
    const j = await r.json();
    return (j.Answer || []).map((a: { data: string }) => String(a.data).replace(/^"|"$/g, "").replace(/"\s*"/g, ""));
  } catch { return []; }
}

async function dnsRecords(name: string, type: "MX" | "NS"): Promise<string[]> {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: "application/dns-json" } });
    if (!r.ok) return [];
    const j = await r.json();
    return (j.Answer || []).map((a: { data: string }) => String(a.data).toLowerCase());
  } catch { return []; }
}

function mailProviderOf(mx: string[]): string | undefined {
  const all = mx.join(" ");
  if (/google\.com|googlemail/.test(all)) return "Google Workspace";
  if (/outlook\.com|protection\.outlook/.test(all)) return "Microsoft 365";
  if (/zoho/.test(all)) return "Zoho";
  if (/secureserver|godaddy/.test(all)) return "GoDaddy";
  if (/wix/.test(all)) return "Wix";
  if (mx.length) return "אחר";
  return undefined;
}
function dnsProviderOf(ns: string[]): string | undefined {
  const all = ns.join(" ");
  const map: Array<[RegExp, string]> = [
    [/cloudflare/, "Cloudflare"], [/wixdns/, "Wix"], [/domaincontrol/, "GoDaddy"], [/azure-dns/, "Azure"],
    [/awsdns/, "Amazon Route 53"], [/googledomains|ns-cloud/, "Google Cloud DNS"], [/livedns\.co\.il/, "LiveDNS"],
    [/hostinger|dns-parking/, "Hostinger"], [/siteground/, "SiteGround"], [/box\.co\.il|cpanel|websitewelcome/, "ספק האחסון (cPanel)"],
    [/interspace/, "אינטרספייס"], [/register\.co\.il|dnslive/, "Register / LiveDNS"], [/shopify/, "Shopify"],
  ];
  return map.find(([re]) => re.test(all))?.[1] ?? (ns.length ? undefined : undefined);
}

// ---------- ניתוח HTML ----------

export function analyzeHtml(html: string, pageUrl: string) {
  const text = strip(html);
  const trackers = TRACKERS.filter(([re]) => re.test(html)).map(([, n]) => n);
  const cms = CMS_HINTS.find(([re]) => re.test(html))?.[1];

  // קישור למדיניות פרטיות
  let privacyUrl: string | undefined;
  for (const a of html.matchAll(/<a\b[^>]*>[\s\S]*?<\/a>/gi)) {
    const tag = a[0];
    if (PRIVACY_LINK.test(strip(tag)) || PRIVACY_LINK.test(attr(tag, "href"))) {
      const href = attr(tag, "href");
      if (href && !href.startsWith("#") && !href.startsWith("javascript")) {
        try { privacyUrl = new URL(href, pageUrl).toString(); } catch { /* ignore */ }
        break;
      }
    }
  }

  // טפסים
  const forms: FormInfo[] = [];
  const formMatches = [...html.matchAll(/<form\b[\s\S]*?<\/form>/gi)];
  formMatches.forEach((m, i) => {
    const f = m[0];
    const inputs = [...f.matchAll(/<(input|select|textarea)\b[^>]*>/gi)].map(x => x[0]);
    const visible = inputs.filter(t => !/type\s*=\s*["'](hidden|submit|button|image|reset)["']/i.test(t));
    if (visible.length === 0) return;                       // טופס חיפוש/טכני
    if (visible.length === 1 && /type\s*=\s*["']search["']|name\s*=\s*["']s["']/i.test(visible[0])) return;

    const fieldNames = visible.map(t => [attr(t, "name"), attr(t, "placeholder"), attr(t, "id"), attr(t, "aria-label")].filter(Boolean).join("|"));
    const labelsText = [...f.matchAll(/<label\b[^>]*>([\s\S]*?)<\/label>/gi)].map(x => strip(x[1])).join(" ");
    const haystack = (fieldNames.join(" ") + " " + labelsText);
    const sensitiveFields = SENSITIVE_FIELDS.filter(([re]) => re.test(haystack)).map(([, n]) => n);

    // טקסט "ליד" הטופס: הטופס עצמו + 600 תווים לפניו ואחריו
    const start = Math.max(0, m.index! - 1500);
    const end = Math.min(html.length, m.index! + f.length + 1500);
    const nearby = strip(html.slice(start, end));
    const noticeHits = NOTICE_PATTERNS.filter(([re]) => re.test(nearby)).map(([, n]) => n);
    const hasPrivacyLink = PRIVACY_LINK.test(html.slice(start, end));

    const checkboxes = visible.filter(t => /type\s*=\s*["']checkbox["']/i.test(t));
    const consentBox = checkboxes.find(t => /(הסכמ|מאשר|אישור|consent|agree|privacy|פרטיות|דיוור|newsletter)/i.test(t + " " + nearby));
    const consentPrechecked = !!consentBox && /\bchecked\b/i.test(consentBox);

    forms.push({
      index: i + 1,
      action: attr(f, "action") || "(אותו עמוד)",
      fieldNames: fieldNames.slice(0, 12),
      sensitiveFields,
      hasNoticeNearby: noticeHits.length >= 3,
      noticeHits,
      hasConsentCheckbox: !!consentBox,
      consentPrechecked,
      hasPrivacyLink,
    });
  });

  // טפסים ללא <form> (Elementor/React) — זיהוי לפי קבוצת inputs
  if (forms.length === 0) {
    const loose = [...html.matchAll(/<input\b[^>]*type\s*=\s*["'](text|email|tel|number)["'][^>]*>/gi)];
    if (loose.length >= 2) {
      const names = loose.map(x => [attr(x[0], "name"), attr(x[0], "placeholder")].filter(Boolean).join("|"));
      const hay = names.join(" ");
      const noticeHits = NOTICE_PATTERNS.filter(([re]) => re.test(text)).map(([, n]) => n);
      forms.push({
        index: 1, action: "(JS)", fieldNames: names.slice(0, 12),
        sensitiveFields: SENSITIVE_FIELDS.filter(([re]) => re.test(hay)).map(([, n]) => n),
        hasNoticeNearby: noticeHits.length >= 3, noticeHits,
        hasConsentCheckbox: /type\s*=\s*["']checkbox["']/i.test(html) && /(הסכמ|מאשר|consent|agree)/i.test(text),
        consentPrechecked: false, hasPrivacyLink: PRIVACY_LINK.test(html),
      });
    }
  }

  // שם העסק ופרטי קשר — כדי למלא את הנוסחים המוכנים
  const ogName = html.match(/<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']{2,80})["']/i)?.[1]
    ?? html.match(/<meta[^>]+content=["']([^"']{2,80})["'][^>]+property=["']og:site_name["']/i)?.[1];
  const title = html.match(/<title[^>]*>([^<]{2,200})<\/title>/i)?.[1];
  const decode = (t: string) => t.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&nbsp;/g, " ").replace(/&#8211;|&ndash;/g, "-").replace(/&#8217;/g, "'").replace(/&[a-z#0-9]+;/gi, "").trim();
  let siteName = ogName ? decode(ogName) : title ? decode(title).split(/\s[|\-–—:]\s/)[0].trim() : undefined;
  if (siteName && (siteName.length < 2 || siteName.length > 60)) siteName = undefined;
  const mails = [...html.matchAll(/mailto:([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})/gi)].map(m => m[1].toLowerCase());
  const textMails = [...text.matchAll(/\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b/gi)].map(m => m[1].toLowerCase());
  const contactEmail = [...mails, ...textMails].find(e => !/(example|sentry|wixpress|wordpress|domain\.com|email\.com|\.png|\.jpg)/.test(e));
  const tels = [...html.matchAll(/tel:([+\d\-\s()]{7,20})/gi)].map(m => m[1].trim());
  const textTels = [...text.matchAll(/(?:^|[^\d])(0(?:[2-489]|5\d|7\d)[-\s]?\d{3}[-\s]?\d{4}|\*\d{4})(?!\d)/g)].map(m => m[1]);
  const contactPhone = [...tels, ...textTels][0];

  return { text, trackers, cms, privacyUrl, forms, siteName, contactEmail, contactPhone };
}

export function analyzePrivacyPolicy(html: string) {
  const text = strip(html);
  const hits = NOTICE_PATTERNS.filter(([re]) => re.test(text)).map(([, n]) => n);
  const mentionsCookies = /(קוקיז|עוגיות|cookies|פיקסל|אנליטיק|google analytics|facebook)/i.test(text);
  const mentionsDirectMail = /(דיוור ישיר|דיוור|ניוזלטר|להסרה|להימחק מרשימת)/.test(text);
  const oldTerms = OLD_TERMS.test(text) && !/בעל השליטה/.test(text);
  return { hits, mentionsCookies, mentionsDirectMail, oldTerms, length: text.length };
}

// ---------- הסריקה המלאה ----------

export async function scan(inputUrl: string): Promise<ScanReport> {
  let url = inputUrl.trim();
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  const host = hostOf(url);
  const findings: Finding[] = [];

  const page = await fetchText(url);
  if (!page.ok) {
    // ננסה http אם https נפל
    const alt = url.replace(/^https:/, "http:");
    const p2 = await fetchText(alt);
    if (!p2.ok) {
      return {
        url: inputUrl, finalUrl: url, scannedAt: new Date().toISOString(), score: 0, exposure: "גבוהה",
        summary: "לא הצלחנו לטעון את האתר. בדוק את הכתובת.", forms: [], trackers: [],
        privacyPolicy: { found: false, hits: [], oldTerms: false }, https: { ok: false }, dns: { spf: false, dmarc: false },
        headers: {}, findings: [{ id: "unreachable", severity: "info", title: "האתר לא נגיש", detail: `סטטוס ${page.status || "שגיאת רשת"}`, law: "—", fix: "ודא שהכתובת נכונה ושהאתר באוויר" }],
        meta: { formsCount: 0, trackersCount: 0 },
      };
    }
    Object.assign(page, p2);
  }

  const https = { ok: page.finalUrl.startsWith("https://"), redirectsHttp: page.finalUrl.startsWith("http://") };
  const a = analyzeHtml(page.text, page.finalUrl);

  // מדיניות פרטיות — נסה קישור, ואם אין — נתיבים מקובלים
  let pp = { found: false as boolean, url: undefined as string | undefined, hits: [] as string[], oldTerms: false, mentionsCookies: false, mentionsDirectMail: false };
  const candidates = [a.privacyUrl, ...["/privacy", "/privacy-policy", "/מדיניות-פרטיות", "/privacy_policy", "/policy"].map(p => new URL(p, page.finalUrl).toString())].filter(Boolean) as string[];
  for (const c of [...new Set(candidates)].slice(0, 4)) {
    const r = await fetchText(c, 8000);
    if (r.ok && /(פרטיות|privacy)/i.test(strip(r.text).slice(0, 5000))) {
      const an = analyzePrivacyPolicy(r.text);
      pp = { found: true, url: c, ...an };
      break;
    }
  }

  // DNS
  const [spfTxt, dmarcTxt, mx, ns] = await Promise.all([dnsTxt(host), dnsTxt(`_dmarc.${host}`), dnsRecords(host, "MX"), dnsRecords(host, "NS")]);
  const dns = { spf: spfTxt.some(t => /^v=spf1/i.test(t)), dmarc: dmarcTxt.some(t => /^v=DMARC1/i.test(t)) };

  // כותרות
  const h = page.headers;
  const headers = {
    "strict-transport-security": !!h.get("strict-transport-security"),
    "content-security-policy": !!h.get("content-security-policy"),
    "x-frame-options": !!h.get("x-frame-options") || /frame-ancestors/i.test(h.get("content-security-policy") || ""),
    "x-content-type-options": !!h.get("x-content-type-options"),
  };

  // ---------- ממצאים ----------
  let score = 100;
  const dock = (n: number) => { score = Math.max(0, score - n); };

  for (const f of a.forms) {
    if (!f.hasNoticeNearby) {
      const missing = NOTICE_PATTERNS.map(([, n]) => n).filter(n => !f.noticeHits.includes(n));
      findings.push({
        id: `form${f.index}-notice`, severity: "critical",
        title: `טופס ${f.index}: חסרה הודעת יידוע מלאה`,
        detail: `ליד הטופס לא נמצאו הפרטים: ${missing.join(", ")}. זו בדיוק ההפרה שבגינה הוטל עיצום על עסק קטן באוגוסט 2026.`,
        law: "סעיף 11 לחוק הגנת הפרטיות (5 פרטי חובה). עיצום: 50 ש\"ח לאדם, מינימום 30,000 ש\"ח; ובנוסף תביעה עד 10,000 ש\"ח ללקוח ללא הוכחת נזק.",
        fix: "להוסיף מתחת לכפתור השליחה 2–3 שורות: למה אוספים, שהמסירה מרצון ומה קורה אם לא, למי מועבר, שם העסק ודרך ליצירת קשר, וזכות לעיין ולתקן — עם קישור למדיניות הפרטיות.",
        evidence: `שדות: ${f.fieldNames.join(", ")}`,
      });
      dock(30);
    }
    if (f.sensitiveFields.length) {
      findings.push({
        id: `form${f.index}-sensitive`, severity: f.hasNoticeNearby ? "high" : "critical",
        title: `טופס ${f.index}: אוסף מידע רגיש (${f.sensitiveFields.join(", ")})`,
        detail: "איסוף מידע כזה בטופס מקוון מכפיל את העיצום (100 ש\"ח לאדם) ועשוי להעלות את רמת האבטחה הנדרשת של המאגר.",
        law: "סעיף 3 — \"מידע בעל רגישות מיוחדת\"; תוספת ראשונה לתקנות אבטחת מידע.",
        fix: "לשאול: האם השדה הזה באמת נחוץ? אם לא — להסיר. אם כן — יידוע מפורט, הסכמה מפורשת, ובדיקת רמת האבטחה בשאלון.",
      });
      dock(15);
    }
    if (f.consentPrechecked) {
      findings.push({ id: `form${f.index}-prechecked`, severity: "high", title: `טופס ${f.index}: תיבת הסכמה מסומנת מראש`, detail: "הסכמה מסומנת מראש אינה \"הסכמה מדעת\" ואינה עומדת בחוק הספאם.", law: "סעיף 3 לחוק הגנת הפרטיות; סעיף 30א לחוק התקשורת.", fix: "להוריד את הסימון המקדים." });
      dock(10);
    }
    if (!f.hasPrivacyLink) {
      findings.push({ id: `form${f.index}-pplink`, severity: "medium", title: `טופס ${f.index}: אין קישור למדיניות פרטיות ליד הטופס`, detail: "היידוע צריך להינתן בד בבד עם הפנייה — לא רק בפוטר.", law: "הנחיית הרשות — חובת יידוע.", fix: "להוסיף קישור \"מדיניות פרטיות\" מתחת לכפתור השליחה." });
      dock(5);
    }
  }

  if (!pp.found) {
    findings.push({ id: "no-privacy-policy", severity: a.forms.length ? "critical" : "high", title: "לא נמצאה מדיניות פרטיות", detail: "לא נמצא עמוד מדיניות פרטיות באתר (נבדקו קישורים ונתיבים מקובלים).", law: "סעיף 11; הנחיית הרשות — חובת יידוע.", fix: "לפרסם מדיניות פרטיות בעברית עם 5 פרטי היידוע, פירוט עוגיות/פיקסלים, ודרך לפנייה לעיון ותיקון." });
    dock(20);
  } else {
    const missing = NOTICE_PATTERNS.map(([, n]) => n).filter(n => !pp.hits.includes(n));
    if (missing.length) {
      findings.push({ id: "pp-incomplete", severity: "high", title: "מדיניות הפרטיות חסרה פרטי חובה", detail: `לא נמצאו: ${missing.join(", ")}.`, law: "סעיף 11 (נוסח אחרי תיקון 13).", fix: "להשלים את הפרטים החסרים.", evidence: pp.url });
      dock(8 * missing.length);
    }
    if (pp.oldTerms) {
      findings.push({ id: "pp-old-terms", severity: "medium", title: "מדיניות הפרטיות כתובה במונחים שלפני תיקון 13", detail: "המדיניות מדברת על \"בעל המאגר\" — המונח בחוק הוא כעת \"בעל השליטה במאגר\". סימן שהמדיניות לא עודכנה מאז 8/2025.", law: "סעיף 3 לחוק (הגדרות).", fix: "לעדכן את המדיניות לנוסח החוק הנוכחי." });
      dock(5);
    }
    if (a.trackers.length && !pp.mentionsCookies) {
      findings.push({ id: "pp-no-cookies", severity: "high", title: "פיקסלים באתר בלי גילוי במדיניות", detail: `האתר מפעיל ${a.trackers.join(", ")} אך המדיניות לא מזכירה עוגיות/פיקסלים/אנליטיקה.`, law: "סעיף 3 — \"מזהה מקוון\" הוא מידע אישי; סעיף 11.", fix: "להוסיף סעיף עוגיות ופיקסלים למדיניות, ולשקול באנר הסכמה." });
      dock(10);
    }
  }

  if (a.trackers.length >= 3) {
    findings.push({ id: "many-trackers", severity: "medium", title: `${a.trackers.length} כלי מעקב באתר`, detail: a.trackers.join(", "), law: "סעיף 3 ו-11; תקנה 15 (מיקור חוץ) — כל ספק כזה מקבל מידע על הגולשים.", fix: "לוודא שכל ספק מופיע במדיניות; להסיר כלים שלא בשימוש." });
    dock(5);
  }

  if (!https.ok) {
    findings.push({ id: "no-https", severity: "critical", title: "האתר לא מוצפן (HTTP)", detail: "פרטים שנשלחים בטופס עוברים בגלוי.", law: "תקנה 14(ב) לתקנות אבטחת מידע — הצפנה בהעברה ברשת ציבורית.", fix: "להתקין תעודת SSL ולהפנות את כל התנועה ל-HTTPS." });
    dock(25);
  }
  if (!headers["strict-transport-security"]) { findings.push({ id: "no-hsts", severity: "low", title: "אין HSTS", detail: "הדפדפן לא מחויב להשתמש ב-HTTPS.", law: "תקנה 14 (אמצעי הגנה).", fix: "להוסיף כותרת Strict-Transport-Security." }); dock(2); }
  if (!headers["x-frame-options"]) { findings.push({ id: "no-xfo", severity: "low", title: "האתר ניתן להטמעה באתרים אחרים (clickjacking)", detail: "אין X-Frame-Options או frame-ancestors.", law: "תקנה 14 (אמצעי הגנה).", fix: "להוסיף כותרת X-Frame-Options: SAMEORIGIN." }); dock(2); }
  if (!headers["x-content-type-options"]) { dock(1); }

  if (!dns.spf) { findings.push({ id: "no-spf", severity: "medium", title: "אין רשומת SPF לדומיין", detail: "כל אחד יכול לשלוח מייל שנראה כאילו הגיע מהעסק שלך.", law: "לא חובה בתקנות, אבל התחזות למייל העסק היא דרך נפוצה לפרצה.", fix: "להוסיף רשומת TXT: v=spf1 include:(ספק המייל) ~all" }); dock(5); }
  if (!dns.dmarc) { findings.push({ id: "no-dmarc", severity: "medium", title: "אין רשומת DMARC", detail: "אין מדיניות שמורה לשרתים לדחות מיילים מזויפים בשם הדומיין.", law: "ראה SPF.", fix: "להוסיף _dmarc TXT: v=DMARC1; p=quarantine; rua=mailto:..." }); dock(5); }

  if (a.cms === "WordPress" || a.cms === "WordPress + Elementor") {
    const ver = page.text.match(/<meta\s+name="generator"\s+content="WordPress\s+([\d.]+)"/i)?.[1];
    if (ver) findings.push({ id: "wp-version", severity: "low", title: `גרסת WordPress גלויה (${ver})`, detail: "חשיפת גרסה מקלה על תוקפים לבחור פרצה מתאימה.", law: "תקנה 13(ג) — עדכוני מערכות.", fix: "להסיר את meta generator ולוודא עדכונים אוטומטיים." });
  }

  // ציון וסיכום
  const sevOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  findings.sort((x, y) => sevOrder.indexOf(x.severity) - sevOrder.indexOf(y.severity));
  const crit = findings.filter(f => f.severity === "critical").length;
  const exposure = crit >= 1 ? "גבוהה" : score < 70 ? "בינונית" : "נמוכה";
  const summary = a.forms.length === 0
    ? `לא נמצאו טפסים לאיסוף פרטים בעמוד הבית. ${pp.found ? "יש מדיניות פרטיות." : "לא נמצאה מדיניות פרטיות."} ${a.trackers.length ? `נמצאו ${a.trackers.length} כלי מעקב.` : ""}`
    : `נמצאו ${a.forms.length} טפסים. ${a.forms.filter(f => !f.hasNoticeNearby).length} מהם בלי הודעת יידוע מלאה. ${pp.found ? "יש מדיניות פרטיות." : "אין מדיניות פרטיות."} ${a.trackers.length ? `${a.trackers.length} כלי מעקב.` : ""}`;

  const report: ScanReport = {
    url: inputUrl, finalUrl: page.finalUrl, scannedAt: new Date().toISOString(), score, exposure, summary,
    forms: a.forms, trackers: a.trackers,
    privacyPolicy: { found: pp.found, url: pp.url, hits: pp.hits, oldTerms: pp.oldTerms },
    https, dns, headers, findings,
    meta: {
      formsCount: a.forms.length, trackersCount: a.trackers.length, cms: a.cms,
      siteName: a.siteName, contactEmail: a.contactEmail, contactPhone: a.contactPhone,
      mailProvider: mailProviderOf(mx), dnsProvider: dnsProviderOf(ns), host,
    },
  };
  addHowTo(report);
  return report;
}
