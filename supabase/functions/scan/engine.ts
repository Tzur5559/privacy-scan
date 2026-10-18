// מנוע סריקה פסיבי — תיקון 13 לחוק הגנת הפרטיות
// רץ על Deno (Supabase Edge) ועל Node 22 (בדיקות). רק web APIs.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;        // עברית, קצר
  detail: string;       // עברית, מה נמצא
  law: string;          // הבסיס המשפטי
  fix: string;          // מה לעשות
  evidence?: string;    // קטע/URL
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
  // סטטיסטיקה פנימית לסקר השוק
  meta: { formsCount: number; trackersCount: number; cms?: string };
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

async function fetchText(url: string, timeoutMs = 12000): Promise<{ ok: boolean; status: number; text: string; finalUrl: string; headers: Headers }> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      redirect: "follow",
      signal: ctrl.signal,
      headers: { "User-Agent": "PrivacyScanIL/0.1 (passive compliance check; +contact via site)", "Accept": "text/html,*/*" },
    });
    const text = r.ok ? await r.text() : "";
    return { ok: r.ok, status: r.status, text, finalUrl: r.url || url, headers: r.headers };
  } catch {
    return { ok: false, status: 0, text: "", finalUrl: url, headers: new Headers() };
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

  return { text, trackers, cms, privacyUrl, forms };
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
  const [spfTxt, dmarcTxt] = await Promise.all([dnsTxt(host), dnsTxt(`_dmarc.${host}`)]);
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

  return {
    url: inputUrl, finalUrl: page.finalUrl, scannedAt: new Date().toISOString(), score, exposure, summary,
    forms: a.forms, trackers: a.trackers,
    privacyPolicy: { found: pp.found, url: pp.url, hits: pp.hits, oldTerms: pp.oldTerms },
    https, dns, headers, findings,
    meta: { formsCount: a.forms.length, trackersCount: a.trackers.length, cms: a.cms },
  };
}
