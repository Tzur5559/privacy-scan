import { staticSafe } from "../supabase/functions/scan/engine.ts";
const bad = ["http://localhost","http://127.0.0.1","http://169.254.169.254/latest/meta-data","http://[::1]/","http://2130706433/","http://0x7f000001/",
  "file:///etc/passwd","ftp://example.com","http://user:pass@example.com","http://example.com:8080/","http://intranet.corp","http://db.local",
  "https://bevtzoskhspkhekkytus.supabase.co/rest/v1/","javascript:alert(1)","http://10.0.0.5","http://nodot"];
const good = ["https://baranetz.com","http://allinn.co.il/","https://www.example.co.il/contact?x=1"];
let fails = 0;
for (const u of bad) if (staticSafe(u)) { console.log("NOT BLOCKED:", u); fails++; }
for (const u of good) if (!staticSafe(u)) { console.log("WRONGLY BLOCKED:", u); fails++; }
console.log(fails ? `FAIL ${fails}` : `OK: ${bad.length} blocked, ${good.length} allowed`);
