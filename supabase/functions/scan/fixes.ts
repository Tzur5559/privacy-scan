// מנוע הפתרונות: לכל ממצא — למה זה חשוב, מה לעשות צעד אחרי צעד, נוסח מוכן להעתקה
// (ממולא בשם העסק ובפרטי הקשר שנמצאו באתר), והוראות לפי הפלטפורמה שזוהתה.
// הנוסחים הם "נוסח לדוגמה" — לפי החלטת הפרויקט, עו"ד פרטיות צריך לאשר אותם לפני שנמכור אותם כמוצר.
import type { HowTo, ScanReport } from "./engine.ts";

type Ctx = {
  name: string;          // שם העסק או [שם העסק]
  contact: string;       // אימייל/טלפון או [אימייל לפניות]
  email?: string;
  host: string;
  cms?: string;
  trackers: string[];
  mailProvider?: string;
  dnsProvider?: string;
  ppUrl?: string;
};

const NAME_PH = "[שם העסק]";
const CONTACT_PH = "[אימייל או טלפון לפניות]";

// ---------- נוסחים ----------

function noticeText(c: Ctx) {
  return `הפרטים שתמסרו בטופס ישמשו את ${c.name} כדי לחזור אליכם ולטפל בפנייה. אינכם חייבים למסור אותם, אך בלעדיהם לא נוכל לחזור אליכם. הפרטים לא יימסרו לאחרים, למעט ספקים שמסייעים לנו בתפעול האתר ובניהול הפניות. אפשר לעיין במידע שנשמר עליכם ולבקש לתקן או למחוק אותו בפנייה ל-${c.contact}. לפרטים נוספים ראו את מדיניות הפרטיות.`;
}

function marketingConsentText(c: Ctx) {
  return `אני מאשר/ת לקבל מ-${c.name} עדכונים ומבצעים בדוא"ל וב-SMS. אפשר להסיר את ההסכמה בכל עת.`;
}

function sensitiveConsentText(c: Ctx) {
  return `אני מסכים/ה ש-${c.name} ישמור את המידע שמסרתי בשדה זה לצורך הטיפול בפנייה בלבד. ידוע לי שאיני חייב/ת למסור אותו.`;
}

function trackersParagraph(c: Ctx) {
  const list = c.trackers.length ? c.trackers.join(", ") : "[שמות הכלים — למשל Google Analytics, Meta Pixel]";
  return `עוגיות וכלי מדידה
באתר פועלים כלים של צדדים שלישיים: ${list}. הכלים האלה אוספים מידע טכני על הגלישה — כמו כתובת IP, סוג הדפדפן, העמודים שבהם ביקרתם ומזהה מקוון של המכשיר — לצורך מדידת התנועה באתר ושיפור הפרסום שלנו. המידע נמסר לספקי הכלים ונשמר אצלם לפי מדיניות הפרטיות שלהם. אפשר לחסום עוגיות בהגדרות הדפדפן; חלק מהאתר עלול לא לעבוד כרגיל.`;
}

const PP_SECTIONS: Record<string, (c: Ctx) => string> = {
  "חובה/רשות ותוצאת אי-הסכמה": () =>
    `האם חובה למסור את המידע
אין חובה חוקית למסור לנו מידע. המסירה תלויה ברצונכם ובהסכמתכם. אם תבחרו שלא למסור פרטים, ייתכן שלא נוכל לחזור אליכם או לספק לכם את השירות.`,
  "מטרת האיסוף": c =>
    `למה אנחנו אוספים את המידע
${c.name} משתמש במידע כדי לחזור לפניות, לתת הצעות מחיר ושירות, לנהל את הקשר עם לקוחות, לשפר את האתר, ובמקרה שנתתם לכך הסכמה מפורשת — לשלוח עדכונים ומבצעים.`,
  "למי יימסר המידע": c =>
    `למי מועבר המידע
איננו מוכרים מידע. אנו מעבירים מידע רק לספקים שעובדים בשבילנו — אחסון האתר, מערכת ניהול הפניות, שליחת הודעות${c.trackers.length ? " וכלי המדידה המפורטים בסעיף העוגיות" : ""} — ורק במידה הנדרשת לתפקידם, או כשהחוק מחייב זאת.`,
  "זהות בעל השליטה ודרכי התקשרות": c =>
    `מי אחראי למידע
בעל השליטה במאגר הוא ${c.name}, [ח.פ./ע.מ.], [כתובת העסק]. לכל שאלה או בקשה בנושא פרטיות: ${c.contact}.`,
  "זכות עיון ותיקון": c =>
    `הזכויות שלכם
אתם רשאים לעיין במידע שנשמר עליכם (סעיף 13 לחוק הגנת הפרטיות), לבקש לתקן או למחוק מידע שאינו נכון, שלם, ברור או מעודכן (סעיף 14), ולבקש להסיר אתכם מרשימת דיוור בכל עת. פנו אלינו ב-${c.contact} ונענה תוך 30 יום.`,
};

function privacyPolicyTemplate(c: Ctx) {
  const today = new Date().toLocaleDateString("he-IL");
  return `מדיניות פרטיות — ${c.name}
עודכן: ${today}

${c.name} מכבד את פרטיותכם. במסמך הזה מוסבר איזה מידע אנחנו אוספים באתר ${c.host}, למה, למי הוא מועבר ומה הזכויות שלכם.

איזה מידע נאסף
מידע שאתם מוסרים בטפסים (שם, טלפון, אימייל ותוכן הפנייה), ומידע טכני שנאסף אוטומטית בזמן הגלישה.

${PP_SECTIONS["מטרת האיסוף"](c)}

${PP_SECTIONS["חובה/רשות ותוצאת אי-הסכמה"](c)}

${PP_SECTIONS["למי יימסר המידע"](c)}

${trackersParagraph(c)}

דיוור
נשלח עדכונים ומבצעים רק למי שנתן הסכמה מפורשת. בכל הודעה יש דרך להסיר את עצמכם, ואפשר גם לפנות אלינו ישירות.

אבטחת מידע
אנו נוקטים אמצעים סבירים לאבטחת המידע, בהתאם לתקנות הגנת הפרטיות (אבטחת מידע). המידע נשמר רק כל עוד הוא נחוץ למטרות שלמעלה.

${PP_SECTIONS["זכות עיון ותיקון"](c)}

${PP_SECTIONS["זהות בעל השליטה ודרכי התקשרות"](c)}

שינויים במדיניות
נעדכן את המסמך הזה כשיהיו שינויים. תאריך העדכון האחרון מופיע בראשו.`;
}

// ---------- הוראות לפי פלטפורמה ----------

function platformAddText(cms?: string) {
  switch (cms) {
    case "WordPress + Elementor":
      return { name: "WordPress + Elementor", steps: [
        "בלוח הבקרה של וורדפרס: עמודים ← העמוד עם הטופס ← עריכה עם Elementor.",
        "גוררים ווידג'ט \"עורך טקסט\" (Text Editor) אל מתחת לטופס, בתוך אותו מקטע.",
        "מדביקים את הנוסח, מסמנים את המילים \"מדיניות הפרטיות\" ומוסיפים להן קישור לעמוד המדיניות.",
        "קטן ואפור זה בסדר — העיקר שייראה לפני הלחיצה על שליחה. לוחצים \"עדכן\".",
        "אם הטופס מופיע בכמה עמודים (פוטר, פופאפ) — חוזרים על זה בכל מקום."] };
    case "WordPress":
      return { name: "WordPress", steps: [
        "אם הטופס הוא Contact Form 7: לוח הבקרה ← \"צור קשר\" ← עריכת הטופס, ומדביקים את הנוסח בשורה מעל [submit].",
        "אם הטופס הוא WPForms / Gravity Forms: מוסיפים לטופס שדה מסוג HTML / תוכן, ומדביקים בו את הנוסח.",
        "אם הטופס הוא בלוק בעורך הרגיל: מוסיפים בלוק \"פסקה\" מיד מתחת לטופס.",
        "מקשרים את המילים \"מדיניות הפרטיות\" לעמוד המדיניות ושומרים."] };
    case "Wix":
      return { name: "Wix", steps: [
        "פותחים את העורך של Wix ועוברים לעמוד עם הטופס.",
        "\"הוספה\" (+) ← טקסט ← פסקה, וממקמים אותה מתחת לכפתור השליחה.",
        "מדביקים את הנוסח, מסמנים \"מדיניות הפרטיות\" ← סמל הקישור ← לעמוד המדיניות.",
        "\"פרסום\" בפינה העליונה."] };
    case "Shopify":
      return { name: "Shopify", steps: [
        "Online Store ← Themes ← Customize, ועוברים לעמוד עם הטופס (בדרך כלל Contact).",
        "בתוך מקטע הטופס: Add block ← Text / Rich text, וממקמים אותו מתחת לטופס.",
        "מדביקים את הנוסח ומקשרים לעמוד המדיניות (Settings ← Policies).",
        "Save."] };
    default:
      return { name: "כל אתר אחר", steps: [
        "מעבירים את הנוסח למי שבנה או מתחזק את האתר, עם בקשה: \"להוסיף מתחת לכל טופס באתר, לפני כפתור השליחה, עם קישור למדיניות הפרטיות\".",
        "זה שינוי של כמה דקות עבור בונה אתרים."] };
  }
}

function platformEditForm(cms: string | undefined, what: "remove" | "uncheck") {
  const verb = what === "remove" ? "מוחקים את השדה (סמל הפח)" : "מכבים את האפשרות \"מסומן כברירת מחדל\" / Default value";
  switch (cms) {
    case "WordPress + Elementor":
      return { name: "WordPress + Elementor", steps: [
        "עריכה עם Elementor ← לוחצים על ווידג'ט הטופס ← לשונית Form Fields.",
        `פותחים את השדה הרלוונטי ו${verb}.`, "לוחצים \"עדכן\"."] };
    case "WordPress":
      return { name: "WordPress", steps: [
        "פותחים את עריכת הטופס בתוסף הטפסים (Contact Form 7 / WPForms / Gravity Forms).",
        what === "remove" ? "מוחקים את השדה. ב-Contact Form 7 — מוחקים את השורה של השדה בתבנית." : "ב-Contact Form 7 מוחקים את המילה default:on מהשדה; בתוספים אחרים מבטלים \"Checked by default\".",
        "שומרים."] };
    case "Wix":
      return { name: "Wix", steps: [
        "בעורך לוחצים על הטופס ← \"עריכת טופס\" / Form settings.",
        what === "remove" ? "בוחרים את השדה ← מחיקה." : "בוחרים את תיבת הסימון ← מבטלים \"מסומן כברירת מחדל\".",
        "\"פרסום\"."] };
    default:
      return { name: "כל אתר אחר", steps: [`לבקש ממי שמתחזק את האתר: ${what === "remove" ? "להסיר את השדה מהטופס" : "שתיבת ההסכמה תופיע ריקה ולא מסומנת מראש"}.`] };
  }
}

function platformPolicyPage(cms?: string) {
  switch (cms) {
    case "WordPress + Elementor":
    case "WordPress":
      return { name: cms, steps: [
        "לוח הבקרה ← הגדרות ← פרטיות: וורדפרס מאפשר לבחור או ליצור \"עמוד מדיניות פרטיות\". יוצרים עמוד חדש.",
        "מדביקים את הנוסח, ממלאים את מה שבסוגריים המרובעים, ומפרסמים. כתובת מומלצת: /privacy-policy.",
        "מופעים ← תפריטים (או עריכת הפוטר ב-Elementor): מוסיפים קישור \"מדיניות פרטיות\" לפוטר, כדי שיופיע בכל עמוד."] };
    case "Wix":
      return { name: "Wix", steps: [
        "בעורך: עמודים ← \"+\" הוספת עמוד ← עמוד ריק. קוראים לו \"מדיניות פרטיות\".",
        "מוסיפים תיבת טקסט ומדביקים את הנוסח.",
        "מוסיפים קישור לעמוד בפוטר (תחתית האתר) ← \"פרסום\"."] };
    case "Shopify":
      return { name: "Shopify", steps: [
        "Settings ← Policies ← Privacy policy. מדביקים את הנוסח במקום הטקסט הקיים ושומרים.",
        "Online Store ← Navigation ← Footer menu: מוודאים שיש קישור ל-Privacy policy."] };
    default:
      return { name: "כל אתר אחר", steps: [
        "מעבירים את הנוסח לבונה האתר עם בקשה: \"ליצור עמוד בכתובת /privacy-policy ולשים אליו קישור בפוטר ומתחת לכל טופס\"."] };
  }
}

function platformHttps(cms?: string) {
  switch (cms) {
    case "Wix": case "Shopify": case "Squarespace": case "Webflow":
      return { name: cms, steps: [`ב-${cms} תעודת SSL ניתנת בחינם ואוטומטית. בהגדרות הדומיין בודקים שהיא פעילה; אם כתוב שהיא ממתינה — בדרך כלל זו בעיה ברשומות ה-DNS של הדומיין.`] };
    case "WordPress + Elementor": case "WordPress":
      return { name: cms, steps: [
        "בלוח הבקרה של חברת האחסון (cPanel / Plesk וכו') מפעילים SSL חינמי (Let's Encrypt / AutoSSL).",
        "בוורדפרס: הגדרות ← כללי ← משנים את שתי הכתובות כך שיתחילו ב-https://.",
        "מתקינים את התוסף Really Simple SSL כדי להפנות את כל העמודים ל-https."] };
    default:
      return { name: "כל אתר אחר", steps: ["פונים לחברת האחסון ומבקשים: \"להפעיל תעודת SSL ולהפנות את כל האתר ל-https\". ברוב החברות זה חינם."] };
  }
}

function platformHeaders(cms: string | undefined, header: "hsts" | "xfo", dnsProvider?: string) {
  const steps: string[] = [];
  if (dnsProvider === "Cloudflare") {
    steps.push(header === "hsts"
      ? "האתר עובר דרך Cloudflare: בלוח הבקרה ← SSL/TLS ← Edge Certificates ← HSTS ← Enable. זה כל מה שצריך."
      : "האתר עובר דרך Cloudflare: Rules ← Transform Rules ← Modify Response Header ← מוסיפים X-Frame-Options עם הערך SAMEORIGIN.");
  }
  if (cms === "WordPress" || cms === "WordPress + Elementor") {
    steps.push("בוורדפרס: מתקינים את התוסף Headers Security Advanced & HSTS WP ומפעילים את הכותרת, או מוסיפים את השורה שלמטה לקובץ ‎.htaccess (שרת Apache).");
  } else if (cms === "Wix" || cms === "Shopify") {
    steps.push(`ב-${cms} אין גישה לכותרות האלה. זה ממצא ברמת "המלצה" בלבד — אפשר לדלג עליו.`);
  } else {
    steps.push("מעבירים את השורה שלמטה למי שמתחזק את השרת/האחסון.");
  }
  return { name: dnsProvider === "Cloudflare" ? "Cloudflare" : cms ?? "כל אתר אחר", steps };
}

function dnsWhere(dnsProvider?: string) {
  if (!dnsProvider) return "נכנסים למקום שבו מנוהלות רשומות ה-DNS של הדומיין (בדרך כלל אצל החברה שבה קניתם את הדומיין או אצל חברת האחסון).";
  if (dnsProvider === "Cloudflare") return "נכנסים ל-Cloudflare ← בוחרים את הדומיין ← DNS ← Records ← Add record.";
  if (dnsProvider === "Wix") return "ב-Wix: הגדרות ← דומיינים ← שלוש הנקודות ליד הדומיין ← ניהול רשומות DNS.";
  if (dnsProvider === "GoDaddy") return "ב-GoDaddy: My Products ← הדומיין ← DNS ← Add New Record.";
  return `ה-DNS של הדומיין מנוהל אצל ${dnsProvider}. נכנסים לשם לניהול רשומות DNS ← הוספת רשומה.`;
}

function spfValue(mailProvider?: string) {
  if (mailProvider === "Google Workspace") return "v=spf1 include:_spf.google.com ~all";
  if (mailProvider === "Microsoft 365") return "v=spf1 include:spf.protection.outlook.com ~all";
  if (mailProvider === "Zoho") return "v=spf1 include:zoho.com ~all";
  if (mailProvider === "GoDaddy") return "v=spf1 include:secureserver.net ~all";
  return "v=spf1 include:[הכתובת שספק המייל שלכם נותן] ~all";
}

// ---------- בניית הפתרון לכל ממצא ----------

function build(id: string, c: Ctx, r: ScanReport): HowTo | undefined {
  const form = id.match(/^form(\d+)-(.+)$/);
  const kind = form ? form[2] : id;

  switch (kind) {
    case "notice":
      return {
        why: "זו ההפרה הנפוצה ביותר והקלה ביותר לגלות — מספיק להיכנס לאתר. הרשות להגנת הפרטיות כבר הטילה עליה עיצום על עסק קטן באוגוסט 2026. העיצום מחושב לפי מספר האנשים שמילאו את הטופס (50 ש\"ח לאדם, מינימום 30,000 ש\"ח), וכל לקוח יכול גם לתבוע עד 10,000 ש\"ח בלי להוכיח נזק.",
        steps: [
          "מעתיקים את נוסח היידוע שלמטה. הוא כולל את חמשת הפרטים שהחוק דורש.",
          "בודקים שהוא נכון לעסק: אם אתם מעבירים את הפרטים גם למישהו אחר (שותף, קבלן משנה, מערכת שיווק) — מוסיפים אותו למשפט \"למי יימסר\".",
          "מדביקים אותו מתחת לטופס, לפני כפתור השליחה, עם קישור למדיניות הפרטיות.",
          "אם אתם שולחים דיוור או מבצעים — מוסיפים לטופס תיבת סימון נפרדת, לא מסומנת מראש, עם נוסח ההסכמה לדיוור.",
          "חוזרים על זה בכל טופס באתר: צור קשר, פופאפים, הרשמה לניוזלטר, הזמנה.",
        ],
        copy: [
          { label: "נוסח יידוע מתחת לטופס", text: noticeText(c) },
          { label: "תיבת הסכמה לדיוור (רק אם שולחים עדכונים/מבצעים)", text: marketingConsentText(c) },
        ],
        platform: platformAddText(c.cms),
        who: "אתם בעצמכם, או בונה האתר",
        time: "כ-10 דקות",
      };

    case "sensitive":
      return {
        why: "מידע רגיש (ת\"ז, בריאות, מידע על ילדים, מצב כלכלי) מכפיל את העיצום ל-100 ש\"ח לאדם, ועלול להעלות את רמת האבטחה שהתקנות דורשות מכל המערכות של העסק. הדרך הכי זולה להיפטר מהסיכון: לא לאסוף את המידע בכלל.",
        steps: [
          "שואלים: האם באמת צריך את השדה הזה כבר בטופס הראשון? ברוב העסקים התשובה היא לא — אפשר לבקש אותו מאוחר יותר, בשיחה.",
          "אם לא צריך — מוחקים את השדה מהטופס.",
          "אם חייבים — הופכים את השדה ללא-חובה, מוסיפים לידו את נוסח ההסכמה, ומוודאים שגם נוסח היידוע הכללי מופיע מתחת לטופס.",
          "בודקים לאן נשלחים הטפסים (מייל, CRM, גיליון) ושרק מי שצריך יכול לראות אותם.",
        ],
        copy: [{ label: "נוסח הסכמה ליד שדה רגיש", text: sensitiveConsentText(c) }],
        platform: platformEditForm(c.cms, "remove"),
        who: "אתם בעצמכם, או בונה האתר",
        time: "כ-5 דקות",
      };

    case "prechecked":
      return {
        why: "הסכמה צריכה להיות פעולה אקטיבית של הגולש. תיבה שמסומנת מראש לא נחשבת הסכמה לא לפי חוק הגנת הפרטיות ולא לפי \"חוק הספאם\" — ושליחת דיוור בלי הסכמה חושפת לתביעה של עד 1,000 ש\"ח לכל הודעה, בלי הוכחת נזק.",
        steps: ["פותחים את הגדרות הטופס.", "מבטלים את הסימון המוקדם בתיבת ההסכמה — היא צריכה להופיע ריקה.", "שומרים ובודקים באתר שהתיבה אכן ריקה."],
        copy: [{ label: "נוסח לתיבת ההסכמה", text: marketingConsentText(c) }],
        platform: platformEditForm(c.cms, "uncheck"),
        who: "אתם בעצמכם, או בונה האתר",
        time: "כ-2 דקות",
      };

    case "pplink":
      return {
        why: "הרשות מצפה שהיידוע יינתן ברגע שאוספים את המידע — כלומר ליד הטופס, ולא רק בקישור בפוטר שאף אחד לא רואה.",
        steps: ["מוסיפים מתחת לכפתור השליחה קישור \"מדיניות הפרטיות\" לעמוד המדיניות.", "הכי פשוט: להדביק את נוסח היידוע המלא (בממצא \"חסרה הודעת יידוע\") — הוא כבר כולל את הקישור."],
        copy: [{ label: "שורה קצרה מתחת לכפתור", text: `בשליחת הטופס אני מאשר/ת את מדיניות הפרטיות של ${c.name}.` }],
        platform: platformAddText(c.cms),
        who: "אתם בעצמכם, או בונה האתר",
        time: "כ-3 דקות",
      };

    case "no-privacy-policy":
      return {
        why: "מדיניות פרטיות היא המקום שבו מפרטים את כל מה שהחוק מחייב לספר לגולשים. בלעדיה אין לעסק שום מסמך להציג אם מגיעה פנייה מהרשות או מלקוח, ואי אפשר לקשר אליה מהטפסים.",
        steps: [
          "מעתיקים את הנוסח לדוגמה שלמטה — הוא כבר ממולא בשם העסק ובכלים שמצאנו באתר.",
          "ממלאים את מה שבסוגריים המרובעים: ח.פ./ע.מ., כתובת העסק.",
          "עוברים עליו ומוחקים או משנים מה שלא נכון לעסק שלכם (למשל אם אתם לא שולחים דיוור).",
          "מפרסמים אותו כעמוד באתר, ומקשרים אליו מהפוטר ומכל טופס.",
          "מומלץ שעורך דין יעבור על הנוסח לפני הפרסום — זו טיוטה, לא ייעוץ משפטי.",
        ],
        copy: [{ label: "מדיניות פרטיות — נוסח לדוגמה", text: privacyPolicyTemplate(c) }],
        platform: platformPolicyPage(c.cms),
        who: "אתם בעצמכם, או בונה האתר",
        time: "כ-30 דקות",
      };

    case "pp-incomplete": {
      const missing = Object.keys(PP_SECTIONS).filter(k => !r.privacyPolicy.hits.includes(k));
      return {
        why: "מדיניות שחסרים בה פרטים שסעיף 11 דורש לא מגינה על העסק — מבחינת הרשות היידוע לא ניתן במלואו.",
        steps: [
          "פותחים את עמוד מדיניות הפרטיות לעריכה.",
          `מוסיפים פסקה לכל אחד מהפרטים החסרים (${missing.length}): ${missing.join(", ")}. הנוסחים מוכנים למטה.`,
          "ממלאים את מה שבסוגריים המרובעים ומעדכנים את תאריך העדכון בראש המסמך.",
        ],
        copy: missing.map(k => ({ label: `פסקה: ${k}`, text: PP_SECTIONS[k](c) })),
        platform: platformPolicyPage(c.cms),
        who: "אתם בעצמכם, או בונה האתר",
        time: "כ-15 דקות",
      };
    }

    case "pp-old-terms":
      return {
        why: "המונח \"בעל המאגר\" הוחלף בתיקון 13 ב\"בעל השליטה במאגר\". זה לא עיצום בפני עצמו, אבל זה סימן ברור שהמדיניות לא עודכנה מאז שהחוק השתנה — וכנראה חסרים בה גם דברים מהותיים.",
        steps: ["מחפשים במדיניות את המילים \"בעל המאגר\" ומחליפים ב\"בעל השליטה במאגר\".", "בהזדמנות הזו עוברים על המדיניות מול הממצאים האחרים בדוח ומעדכנים את תאריך העדכון."],
        copy: [{ label: "פסקת זהות בעל השליטה", text: PP_SECTIONS["זהות בעל השליטה ודרכי התקשרות"](c) }],
        platform: platformPolicyPage(c.cms),
        who: "אתם בעצמכם",
        time: "כ-5 דקות",
      };

    case "pp-no-cookies":
      return {
        why: "מאז תיקון 13, \"מזהה מקוון\" (כמו מזהה עוגייה או פיקסל) הוא מידע אישי. כלים כמו פיקסל של פייסבוק מעבירים מידע על כל גולש לחברה אחרת — וצריך לספר על זה במדיניות.",
        steps: ["מוסיפים למדיניות הפרטיות את סעיף העוגיות שלמטה (הכלים שמצאנו כבר כתובים בו).", "אם יש כלים שלא משתמשים בהם — עדיף להסיר אותם מהאתר."],
        copy: [{ label: "סעיף עוגיות וכלי מדידה", text: trackersParagraph(c) }],
        platform: platformPolicyPage(c.cms),
        who: "אתם בעצמכם",
        time: "כ-5 דקות",
      };

    case "many-trackers":
      return {
        why: "כל כלי כזה הוא ספק שמקבל מידע על הגולשים שלכם. ככל שיש יותר כלים — יותר צריך לפרט במדיניות, ויותר סיכוי שאחד מהם שוכח לגמרי שהוא שם.",
        steps: [
          `עוברים על הרשימה: ${c.trackers.join(", ")}. לכל כלי שואלים — מישהו באמת מסתכל על הנתונים שלו?`,
          "מסירים כלים שלא בשימוש (בדרך כלל דרך Google Tag Manager או הגדרות האתר/התוספים).",
          "את הכלים שנשארים מפרטים במדיניות הפרטיות — הנוסח מוכן למטה.",
        ],
        copy: [{ label: "סעיף עוגיות וכלי מדידה", text: trackersParagraph(c) }],
        who: "אתם בעצמכם, או מי שמנהל לכם את הפרסום",
        time: "כ-20 דקות",
      };

    case "no-https":
      return {
        why: "בלי הצפנה, כל מה שגולש מקליד בטופס עובר ברשת בגלוי. תקנות אבטחת המידע מחייבות הצפנה כשמעבירים מידע ברשת ציבורית, והדפדפנים גם מציגים לגולשים \"האתר לא מאובטח\".",
        steps: ["מפעילים תעודת SSL (ברוב המקרים בחינם).", "מפנים את כל הכתובות מ-http ל-https.", "נכנסים לאתר ובודקים שמופיע סמל המנעול ליד הכתובת."],
        platform: platformHttps(c.cms),
        who: "חברת האחסון או בונה האתר",
        time: "כ-15 דקות",
      };

    case "no-hsts":
      return {
        why: "HSTS מורה לדפדפן להשתמש תמיד בגרסה המוצפנת של האתר, גם אם מישהו מנסה להפנות אותו לגרסה לא מוצפנת. זו המלצה טכנית — לא דרישה מפורשת בחוק.",
        steps: ["מוסיפים לאתר את כותרת האבטחה שלמטה.", "בודקים שהאתר ממשיך לעבוד כרגיל."],
        copy: [{ label: "שורה ל-‎.htaccess (שרתי Apache)", text: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"', ltr: true }],
        platform: platformHeaders(c.cms, "hsts", c.dnsProvider),
        who: "בונה האתר או חברת האחסון",
        time: "כ-5 דקות",
      };

    case "no-xfo":
      return {
        why: "בלי ההגדרה הזו, אתר אחר יכול להציג את האתר שלכם בתוך מסגרת ולגרום לגולשים ללחוץ על דברים בלי לשים לב (clickjacking). המלצה טכנית — לא דרישה מפורשת בחוק.",
        steps: ["מוסיפים לאתר את כותרת האבטחה שלמטה."],
        copy: [{ label: "שורה ל-‎.htaccess (שרתי Apache)", text: 'Header always set X-Frame-Options "SAMEORIGIN"', ltr: true }],
        platform: platformHeaders(c.cms, "xfo", c.dnsProvider),
        who: "בונה האתר או חברת האחסון",
        time: "כ-5 דקות",
      };

    case "no-spf": {
      return {
        why: "בלי SPF כל אחד יכול לשלוח מייל שנראה כאילו הגיע מהכתובת של העסק — למשל \"חשבונית\" מזויפת ללקוחות שלכם. זו אחת הדרכים הנפוצות להונות לקוחות ולפרוץ לעסקים.",
        steps: [
          dnsWhere(c.dnsProvider),
          "מוסיפים רשומה מסוג TXT. בשדה השם (Name / Host) כותבים @ .",
          `בשדה הערך מדביקים את הערך שלמטה${c.mailProvider && c.mailProvider !== "אחר" ? ` (הוא מותאם ל-${c.mailProvider}, שזיהינו כספק המייל שלכם)` : " ומשלימים את הכתובת שספק המייל שלכם נותן"}.`,
          "אם אתם שולחים מיילים גם ממערכת נוספת (דיוור, חשבוניות) — מוסיפים גם אותה לאותה רשומה. אסור שיהיו שתי רשומות SPF.",
        ],
        copy: [{ label: "ערך רשומת SPF", text: spfValue(c.mailProvider), ltr: true }],
        platform: c.dnsProvider ? { name: c.dnsProvider, steps: [dnsWhere(c.dnsProvider)] } : undefined,
        who: "מי שמנהל את הדומיין או את המייל",
        time: "כ-10 דקות",
      };
    }

    case "no-dmarc": {
      const rua = c.email && c.email.endsWith(c.host) ? c.email : `dmarc@${c.host}`;
      return {
        why: "DMARC אומר לשרתי המייל בעולם מה לעשות עם מייל מזויף בשם הדומיין שלכם. בלעדיו גם SPF לא מגן עד הסוף.",
        steps: [
          dnsWhere(c.dnsProvider),
          "מוסיפים רשומה מסוג TXT. בשדה השם כותבים _dmarc .",
          "מדביקים את הערך הראשון (מצב מעקב בלבד — לא חוסם כלום). כדאי להתחיל ככה כדי לא לחסום בטעות מיילים אמיתיים.",
          "אחרי שבועיים-שלושה, אם הכל תקין, מחליפים לערך השני (מצב הגנה).",
        ],
        copy: [
          { label: "שלב 1 — מעקב", text: `v=DMARC1; p=none; rua=mailto:${rua}`, ltr: true },
          { label: "שלב 2 — הגנה (אחרי 2–3 שבועות)", text: `v=DMARC1; p=quarantine; rua=mailto:${rua}`, ltr: true },
        ],
        platform: c.dnsProvider ? { name: c.dnsProvider, steps: [dnsWhere(c.dnsProvider)] } : undefined,
        who: "מי שמנהל את הדומיין או את המייל",
        time: "כ-10 דקות",
      };
    }

    case "wp-version":
      return {
        why: "כשגרסת וורדפרס גלויה, תוקף יודע בדיוק איזו פרצה לנסות. תקנות אבטחת המידע מחייבות לעדכן מערכות — וגרסה ישנה וגלויה היא שילוב גרוע.",
        steps: [
          "לוח הבקרה ← עדכונים: מעדכנים את וורדפרס, התבנית והתוספים לגרסה האחרונה.",
          "מסתירים את מספר הגרסה: תוסף אבטחה (למשל Wordfence או Solid Security) עושה את זה בלחיצה, או מוסיפים את השורה שלמטה לקובץ functions.php של תבנית-הבת.",
          "מפעילים עדכונים אוטומטיים לתוספים.",
        ],
        copy: [{ label: "שורה ל-functions.php", text: "remove_action('wp_head', 'wp_generator');", ltr: true }],
        who: "בונה האתר",
        time: "כ-15 דקות",
      };
  }
  return undefined;
}

export function addHowTo(r: ScanReport) {
  const m = r.meta;
  const contact = m.contactEmail ?? m.contactPhone ?? CONTACT_PH;
  const c: Ctx = {
    name: m.siteName || NAME_PH,
    contact,
    email: m.contactEmail,
    host: m.host || (() => { try { return new URL(r.finalUrl).hostname.replace(/^www\./, ""); } catch { return ""; } })(),
    cms: m.cms,
    trackers: r.trackers,
    mailProvider: m.mailProvider,
    dnsProvider: m.dnsProvider,
    ppUrl: r.privacyPolicy.url,
  };
  for (const f of r.findings) {
    const h = build(f.id, c, r);
    if (h) f.howTo = h;
  }
}
