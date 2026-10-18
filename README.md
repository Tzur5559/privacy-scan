# בדיקת פרטיות לאתר — תיקון 13

סורק חינמי שבודק אם אתר של עסק ישראלי עומד בחובת היידוע (סעיף 11) ובדרישות בסיסיות של תיקון 13 לחוק הגנת הפרטיות.

## מבנה

- `index.html` — דף הנחיתה (GitHub Pages). מדבר עם השרת דרך כתובת קבועה.
- `supabase/functions/scan/` — הפונקציה שרצה ב-Supabase (פרויקט Baranetz-portal):
  - `engine.ts` — מנוע הסריקה (פסיבי בלבד: קריאת HTML, DNS, כותרות).
  - `index.ts` — שער: POST {url} מחזיר דוח, POST {action:"lead"} שומר ליד, הגבלת קצב 10 לשעה ל-IP.
- `tests/` — אתרי דוגמה ובדיקות. הרצה: `node --experimental-strip-types tests/test.mjs`

## נתונים

טבלאות `pscan_scans` ו-`pscan_leads` ב-Supabase, עם RLS וללא גישה ציבורית. רק הפונקציה כותבת.

## פריסה

- הדף: כל דחיפה ל-`main` מתפרסמת אוטומטית ב-GitHub Pages.
- הפונקציה: נפרסת ל-Supabase בנפרד (לא אוטומטית מהריפו).
