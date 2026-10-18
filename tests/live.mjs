import { scan } from "../supabase/functions/scan/engine.ts";
const r = await scan(process.argv[2]);
console.log(JSON.stringify({ ...r, findings: r.findings.map(f => `[${f.severity}] ${f.title}`) }, null, 1));
