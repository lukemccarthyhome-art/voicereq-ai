(async ()=>{
  const db = require('../database-adapter');
  const projectId = '1';
  const sessions = await db.getSessionsByProject(projectId);
  let reqText = '';
  sessions.forEach(s=>{ try{ const t = JSON.parse(s.transcript || '[]'); t.forEach(m=> reqText += `${m.role}: ${m.text}\n`); }catch(e){} });
  const files = await db.getFilesByProject(projectId);
  files.forEach(f=> reqText += `FILE ${f.original_name}: ${(f.extracted_text||'').substring(0,200)}\n`);
  const OPENAI_KEY = process.env.OPENAI_API_KEY;
  const prompt = `You are an expert software architect. Given the project conversation and files, produce a SOLUTION DESIGN document.\n\nINSTRUCTIONS:\n- Output valid JSON only.\n- JSON keys: \"design\" (string, markdown with sections: Summary, Architecture, Components, Data Flow, APIs, Security, Integrations, Acceptance Criteria, Risks), \"questions\" (array of strings, outstanding clarifying questions), \"summary\" (2-3 sentence summary).\n- Do NOT include raw chat transcript in the design. Distill requirements into decisions and assumptions.\n\nCONTEXT:\n${reqText.substring(0,15000)}\n`;
  try{
    const r = await fetch('https://api.openai.com/v1/chat/completions',{
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+OPENAI_KEY},
      body: JSON.stringify({ model: 'gpt-5-mini', temperature:1, max_completion_tokens:2000, messages:[{role:'system',content:'You are an expert software architect and business analyst.'},{role:'user',content:prompt}] })
    });
    console.log('status', r.status);
    const t = await r.text();
    console.log(t);
  } catch(e){ console.error(e); }
})();
