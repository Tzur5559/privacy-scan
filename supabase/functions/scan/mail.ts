// שליחת מיילים. שני ספקים נתמכים, ההחלפה ביניהם היא רק עניין של סוד ב-Supabase:
//  1. Cloudflare Email Service — CF_ACCOUNT_ID + CF_EMAIL_TOKEN. דורש דומיין שמנוהל ב-Cloudflare.
//     חינם לכתובות שאומתו בחשבון (ההתראות והקודים שלנו); שליחה ללקוחות דורשת Workers Paid.
//  2. Brevo — BREVO_API_KEY. לא דורש דומיין, חינם עד 300 מיילים ביום.
// אם שניהם מוגדרים, Cloudflare קודם.
export const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

export function mailProvider(): "cloudflare" | "brevo" | null {
  if (Deno.env.get("CF_ACCOUNT_ID") && Deno.env.get("CF_EMAIL_TOKEN")) return "cloudflare";
  if (Deno.env.get("BREVO_API_KEY")) return "brevo";
  return null;
}
export function mailConfigured() {
  return mailProvider() !== null;
}

type MailOpts = {
  to: string[]; subject: string; html: string; text: string;
  senderEmail: string; senderName: string; replyTo?: string;
};

export async function sendMail(opts: MailOpts): Promise<{ ok: boolean; error?: string }> {
  const provider = mailProvider();
  if (!provider) return { ok: false, error: "no_key" };
  if (!opts.to.length) return { ok: false, error: "no_recipients" };
  return provider === "cloudflare" ? sendCloudflare(opts) : sendBrevo(opts);
}

async function sendCloudflare(opts: MailOpts): Promise<{ ok: boolean; error?: string }> {
  const acc = Deno.env.get("CF_ACCOUNT_ID")!, token = Deno.env.get("CF_EMAIL_TOKEN")!;
  if (!/^[0-9a-f]{32}$/i.test(acc)) return { ok: false, error: "bad_account" };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${acc}/email/sending/send`, {
      method: "POST",
      signal: ctrl.signal,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        from: { email: opts.senderEmail, name: opts.senderName },
        to: opts.to,
        subject: opts.subject,
        html: opts.html,
        text: opts.text,
        ...(opts.replyTo ? { replyTo: opts.replyTo } : {}),
      }),
    });
    const j = await r.json().catch(() => null) as { success?: boolean; errors?: { code: number; message: string }[] } | null;
    if (!r.ok || !j?.success) {
      console.error("cf mail", r.status, JSON.stringify(j?.errors ?? []).slice(0, 200));
      return { ok: false, error: `provider_${r.status}` };
    }
    return { ok: true };
  } catch (e) {
    console.error("cf mail fetch", (e as Error)?.name);
    return { ok: false, error: "provider_unreachable" };
  } finally {
    clearTimeout(t);
  }
}

async function sendBrevo(opts: MailOpts): Promise<{ ok: boolean; error?: string }> {
  const key = Deno.env.get("BREVO_API_KEY")!;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      signal: ctrl.signal,
      headers: { "api-key": key, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        sender: { email: opts.senderEmail, name: opts.senderName },
        to: opts.to.map(email => ({ email })),
        subject: opts.subject,
        htmlContent: opts.html,
        textContent: opts.text,
        ...(opts.replyTo ? { replyTo: { email: opts.replyTo } } : {}),
      }),
    });
    if (!r.ok) {
      const body = await r.text().catch(() => "");
      console.error("brevo", r.status, body.slice(0, 200));
      return { ok: false, error: `provider_${r.status}` };
    }
    return { ok: true };
  } catch (e) {
    console.error("brevo fetch", (e as Error)?.name);
    return { ok: false, error: "provider_unreachable" };
  } finally {
    clearTimeout(t);
  }
}

export function wrap(title: string, inner: string) {
  return `<!doctype html><html dir="rtl" lang="he"><body style="margin:0;background:#f4f5fb;font-family:Arial,Helvetica,sans-serif;color:#1e1b4b">
<div style="max-width:560px;margin:24px auto;background:#fff;border-radius:12px;border:1px solid #e3e5f2;overflow:hidden">
<div style="background:#4338ca;color:#fff;padding:16px 20px;font-size:18px;font-weight:bold">${esc(title)}</div>
<div style="padding:20px;font-size:15px;line-height:1.6">${inner}</div>
<div style="padding:12px 20px;font-size:12px;color:#6b6f8a;border-top:1px solid #eef0f7">פרטיות בטוח · הודעה אוטומטית ממערכת הניהול</div>
</div></body></html>`;
}
