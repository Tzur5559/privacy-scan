import { readFileSync } from "node:fs";
import { analyzeHtml, analyzePrivacyPolicy } from "../supabase/functions/scan/engine.ts";

for (const f of ["bad", "good"]) {
  const html = readFileSync(new URL(`./${f}.html`, import.meta.url), "utf8");
  const a = analyzeHtml(html, "https://example.co.il/");
  console.log(`\n=== ${f} ===`);
  console.log("cms:", a.cms, "| trackers:", a.trackers);
  console.log("privacyUrl:", a.privacyUrl);
  for (const fm of a.forms) console.log(JSON.stringify(fm, null, 1));
}
const pp = analyzePrivacyPolicy(`<p>בעל המאגר שומר את המידע למטרת שירות. המידע לא יועבר. צור קשר info@x.co.il. זכות עיון. מסירת המידע מרצון.</p>`);
console.log("\npolicy:", pp);
