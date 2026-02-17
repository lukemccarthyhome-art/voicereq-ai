const fs = require('fs');
const path = require('path');
const db = require('../database-adapter');
(async ()=>{
  try{
    const projectId = process.argv[2] || '1';
    const sessions = await db.getSessionsByProject(projectId);
    let reqText = '';
    sessions.forEach(s=>{ try{ const t = JSON.parse(s.transcript||'[]'); t.forEach(m=> reqText += `${m.role}: ${m.text}
`) }catch(e){} });
    const files = await db.getFilesByProject(projectId);
    files.forEach(f=> reqText += `FILE ${f.original_name}: ${(f.extracted_text||'').substring(0,200)}
`);

    const summarizeRequirements = (text)=> (text||'').split(/\n+/).map(l=>l.trim()).filter(Boolean).slice(0,8).join(' ');
    const buildStrictPrompt = (context, prevAnswers)=>{
      return `You are an expert software architect. Produce a SOLUTION DESIGN for the project using the context below.

REQUIREMENTS:
- Output valid JSON only.
- JSON schema: {
    "summary": string (2-3 sentences),
    "design": { "Summary":string, "Dependencies":string, "ClientResponsibilities":string, "Architecture":string, "Components":string, "DataFlow":string, "APIs":string, "Security":string, "Integrations":string, "AcceptanceCriteria":string, "Risks":string },
    "questions": [ { "id": number, "text": string, "assumption": string } ]
  }
- The questions array MUST contain only clarifying questions about MISSING or AMBIGUOUS information required to finalise the design. If nothing is missing, return an empty array.
- Each question should include a short "assumption" explaining why it is needed. Use numeric ids starting at 1.
- Do NOT include raw transcript lines in the design. Distill requirements into decisions, assumptions, and remaining gaps.

CONTEXT:
${context}

PREVIOUS_ANSWERS:
${prevAnswers || 'None'}`;
    }

    const summary = summarizeRequirements(reqText);
    let llmDesignMarkdown = '';
    let llmQuestions = [];
    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (OPENAI_KEY) {
      try {
        const model = process.env.LLM_MODEL || process.env.OPENAI_MODEL || 'gpt-3.5-turbo';
        const prompt = buildStrictPrompt(reqText.substring(0,15000), '');
        const resp = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + OPENAI_KEY },
          body: JSON.stringify({ model: model, temperature: 1, max_completion_tokens: 1500, messages: [{ role: 'system', content: 'You are an expert software architect and business analyst.' }, { role: 'user', content: prompt }] })
        });
        if (resp.ok) {
          const data = await resp.json();
          let content = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
          try {
            const jsonStart = content.indexOf('{');
            const jsonText = jsonStart>=0 ? content.slice(jsonStart) : content;
            const parsed = JSON.parse(jsonText);
            llmDesignMarkdown = parsed.design ? (typeof parsed.design === 'string' ? parsed.design : JSON.stringify(parsed.design)) : (parsed.summary || '');
            llmQuestions = parsed.questions || [];
          } catch (e) {
            llmDesignMarkdown = content || '';
            llmQuestions = [];
          }
        } else {
          console.error('LLM call failed', await resp.text());
        }
      } catch (e) { console.error('LLM error', e.message); }
    } else {
      // fallback stub
      llmDesignMarkdown = `## Summary

${summary}

## Dependencies

- Morti Projects API

## ClientResponsibilities

- Provide branding assets

## Architecture

- Express backend, SQLite/Postgres

## Components

- Proposal generator service

## DataFlow

- Input -> Generator -> Proposal -> Customer Portal

## APIs

- /api/proposals/create

## Security

- JWT, HTTPS

## Integrations

- Morti Projects, Customer Portal

## AcceptanceCriteria

- Generates proposal, approval flow, online signing

## Risks

- Integration complexity`;
      llmQuestions = [];
    }

    // build designHtml from markdown naïvely
    const escape = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const md = llmDesignMarkdown;
    let html = '';
    if (md && md.trim()) {
      // simple split by headings
      const parts = md.split(/\n## /).map(p=>p.trim());
      parts.forEach((p,i)=>{
        if (i===0 && p.startsWith('## Summary')) p = p.replace(/^## Summary\s*/,'');
        const lines = p.split(/\n+/);
        const title = lines[0].replace(/^##\s*/,'');
        const body = lines.slice(1).join('\n').trim();
        if (title && body) html += `<h3>${escape(title)}</h3><p>${escape(body).replace(/\n/g,'<br/>')}</p>`;
      });
    }

    const design = { id: `design-${projectId}-${Date.now()}`, projectId, createdAt: new Date().toISOString(), owner: 'admin', version: 1, status: 'draft', designMarkdown: llmDesignMarkdown, designHtml: html, questions: llmQuestions, chat: [], answers: [], raw_output: '' };

    const designsDir = path.join(__dirname, '..', 'data', 'designs');
    fs.mkdirSync(designsDir, { recursive: true });
    const filePath = path.join(designsDir, design.id + '.json');
    fs.writeFileSync(filePath, JSON.stringify(design, null, 2));
    // Mirror questions into project record for consistency (if DB helper available)
    try {
      if (db.updateProjectDesignQuestions) {
        await db.updateProjectDesignQuestions(projectId, JSON.stringify(design.questions || []));
      }
    } catch (e) { console.warn('Failed to mirror questions to project record:', e.message); }
    console.log('Wrote design file:', filePath);
  }catch(e){ console.error(e); process.exit(1); }
})();
