// Extracted session logic for the VoiceReq AI voice interface
// This supports project/session integration for database persistence

class VoiceSession {
    constructor() {
        this.vapi = null;
        this.messages = [];
        this.uploadedFiles = [];
        this.inCall = false;
        this.isMuted = false;
        this.micMuted = false;
        this.aiHeld = false;
        this.requirements = {};
        this.sessionContext = {
            projectName: '',
            topicsCovered: [],
            keyFacts: [],
            currentTopic: '',
            filesUploaded: []
        };
        
        // Get project and session from URL params
        const urlParams = new URLSearchParams(window.location.search);
        this.projectId = urlParams.get('project');
        this.sessionId = urlParams.get('session');
        
        console.log('🎯 Session initialized', { projectId: this.projectId, sessionId: this.sessionId });
        
        this.initVapi();
        this.setupAutoSave();
        this.loadSessionData();
    }

    async loadSessionData() {
        if (!this.sessionId) return;
        
        try {
            const response = await fetch(`/api/sessions/${this.sessionId}`);
            if (!response.ok) throw new Error('Failed to load session');
            
            const sessionData = await response.json();
            
            // Restore conversation state
            if (sessionData.transcript) {
                this.messages = JSON.parse(sessionData.transcript);
                this.renderTranscript();
            }
            
            if (sessionData.requirements) {
                this.requirements = JSON.parse(sessionData.requirements);
                this.renderRequirements();
            }
            
            if (sessionData.context) {
                this.sessionContext = { ...this.sessionContext, ...JSON.parse(sessionData.context) };
            }
            
            // Restore files if available
            if (sessionData.files && sessionData.files.length > 0) {
                this.uploadedFiles = sessionData.files;
                window.fileContents = {};
                
                sessionData.files.forEach(file => {
                    if (file.extracted_text) {
                        window.fileContents[file.original_name] = file.extracted_text;
                    }
                });
                
                this.renderFileChips();
            }
            
            console.log('✅ Session data loaded', { 
                messages: this.messages.length, 
                requirements: Object.keys(this.requirements).length,
                files: sessionData.files ? sessionData.files.length : 0
            });
            
        } catch (e) {
            console.error('Failed to load session:', e);
        }
    }

    setupAutoSave() {
        // Auto-save every 30 seconds during active session
        setInterval(() => {
            if (this.sessionId && (this.messages.length > 0 || Object.keys(this.requirements).length > 0)) {
                this.saveSession();
            }
        }, 30000);
        
        // Save on page unload
        window.addEventListener('beforeunload', () => {
            if (this.sessionId) {
                navigator.sendBeacon('/api/sessions/' + this.sessionId + '/save', JSON.stringify({
                    transcript: this.messages,
                    requirements: this.requirements,
                    context: this.sessionContext,
                    status: this.inCall ? 'active' : 'paused'
                }));
            }
        });
    }

    async saveSession() {
        if (!this.sessionId) return;
        
        try {
            await fetch(`/api/sessions/${this.sessionId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    transcript: this.messages,
                    requirements: this.requirements,
                    context: this.sessionContext,
                    status: this.inCall ? 'active' : 'paused'
                })
            });
            console.log('💾 Session auto-saved');
        } catch (e) {
            console.error('Failed to save session:', e);
        }
    }

    initVapi() {
        if (this.vapi) return;
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/gh/VapiAI/html-script-tag@latest/dist/assets/index.js';
        script.defer = true;
        script.async = true;
        script.onload = () => {
            if (window.vapiSDK) {
                this.vapi = window.vapiSDK.run({
                    apiKey: 'b34ed3bb-5c71-43df-a191-9b91568a329b',
                    assistant: '55bd93be-541f-4870-ae3e-0c97763c12b3',
                    config: { hide: true }
                });
                this.setupEvents();
                console.log('✅ Vapi SDK loaded');
            }
        };
        document.head.appendChild(script);
    }

    setupEvents() {
        this.vapi.on('call-start', () => {
            this.inCall = true;
            this.setStatus('listening', 'Listening', 'Speak naturally');
            document.getElementById('callBtn').classList.add('active');
            document.getElementById('callBtn').innerHTML = '📵 End';
            document.getElementById('muteBtn').classList.remove('hidden');
            document.getElementById('micBtn').classList.remove('hidden');
        });

        this.vapi.on('call-end', () => {
            this.inCall = false; 
            this.isMuted = false; 
            this.micMuted = false;
            this.aiHeld = false;
            this.setStatus('', 'Session Paused', 'Tap Start to resume where you left off');
            document.getElementById('callBtn').classList.remove('active');
            document.getElementById('callBtn').innerHTML = '📞 Resume';
            document.getElementById('muteBtn').classList.add('hidden');
            document.getElementById('micBtn').classList.add('hidden');
            this.resetMuteButtons();
            this.saveSession(); // Save on call end
        });

        this.vapi.on('speech-start', () => {
            if (this.aiHeld) {
                // AI tried to speak while on hold — interrupt it immediately
                try { this.vapi.say(' ', false, false); } catch(e) {}
                this._muteRemoteAudio(true);
                return;
            }
            this.setStatus('speaking', 'AI Speaking', 'Press "Hold AI" to pause');
        });
        this.vapi.on('speech-end', () => {
            if (this.aiHeld) return;
            this.setStatus('listening', 'Listening', 'Your turn');
        });

        this.vapi.on('volume-level', (level) => {
            document.getElementById('volumeLevel').style.width = (level * 100) + '%';
        });

        this.vapi.on('message', (msg) => {
            if (msg.type === 'transcript' && msg.transcriptType === 'final') {
                const role = msg.role === 'assistant' ? 'ai' : 'user';
                // While AI is held, suppress AI messages from transcript display
                if (this.aiHeld && role === 'ai') return;
                this.messages.push({ role, text: msg.transcript });
                this.addTranscriptMsg(role, msg.transcript);
                
                if (role === 'user') {
                    this.sessionContext.keyFacts.push(msg.transcript);
                }
                
                if (role === 'ai') {
                    this.trackTopics(msg.transcript);
                }
                
                // Auto-save after every few messages
                if (this.messages.length % 4 === 0) {
                    this.saveSession();
                }
            }
        });

        this.vapi.on('error', (err) => {
            console.error('Vapi error:', err);
            this.showError('Voice error: ' + (err.message || JSON.stringify(err)));
        });
    }

    trackTopics(aiText) {
        const lower = aiText.toLowerCase();
        if (lower.match(/project|name|overview|what are you build/)) this.sessionContext.topicsCovered.push('project_basics');
        if (lower.match(/stakeholder|user|who|audience/)) this.sessionContext.topicsCovered.push('stakeholders');
        if (lower.match(/feature|function|should|need to do/)) this.sessionContext.topicsCovered.push('functional');
        if (lower.match(/performance|security|scale|non-func/)) this.sessionContext.topicsCovered.push('non_functional');
        if (lower.match(/budget|timeline|constraint|deadline/)) this.sessionContext.topicsCovered.push('constraints');
        if (lower.match(/success|goal|metric|measure/)) this.sessionContext.topicsCovered.push('success_criteria');
        this.sessionContext.topicsCovered = [...new Set(this.sessionContext.topicsCovered)];
    }

    async toggleCall() {
        if (this.inCall) { 
            if (this.vapi) this.vapi.stop(); 
        } else {
            await this.startCall();
        }
    }

    buildFileContext() {
        const fc = window.fileContents || {};
        if (Object.keys(fc).length === 0) return '';
        let ctx = 'UPLOADED DOCUMENTS:\n';
        for (const [name, content] of Object.entries(fc)) {
            ctx += '\n--- ' + name + ' ---\n' + content.substring(0, 4000) + '\n';
        }
        return ctx;
    }

    buildContextSummary() {
        let summary = '';
        
        // Gathered requirements
        const reqEntries = Object.entries(this.requirements);
        if (reqEntries.length > 0) {
            summary += 'REQUIREMENTS GATHERED SO FAR:\n';
            reqEntries.forEach(([cat, items]) => {
                summary += '\n' + cat + ':\n';
                items.forEach(r => summary += '- ' + r + '\n');
            });
        }

        // Topics covered
        if (this.sessionContext.topicsCovered.length > 0) {
            summary += '\nTOPICS ALREADY COVERED (do NOT repeat): ' + this.sessionContext.topicsCovered.join(', ') + '\n';
        }

        // Files uploaded with contents
        const fc = window.fileContents || {};
        if (Object.keys(fc).length > 0) {
            summary += '\nFILES UPLOADED AND THEIR CONTENTS:\n';
            for (const [name, content] of Object.entries(fc)) {
                summary += '\n--- ' + name + ' ---\n' + content.substring(0, 3000) + '\n';
            }
        }

        // Full conversation transcript
        if (this.messages.length > 0) {
            summary += '\nFULL CONVERSATION TRANSCRIPT:\n';
            this.messages.forEach(m => {
                summary += (m.role === 'ai' ? 'Assistant' : 'User') + ': ' + m.text + '\n';
            });
        }

        return summary;
    }

    async startCall() {
        if (!this.vapi) { 
            this.showError('SDK loading...'); 
            return; 
        }
        
        this.setStatus('thinking', 'Connecting...', 'Setting up voice channel');
        
        try {
            if (this.messages.length > 0) {
                const context = this.buildContextSummary();
                const allTopics = ['project_basics', 'stakeholders', 'functional', 'non_functional', 'constraints', 'success_criteria'];
                const remaining = allTopics.filter(t => !this.sessionContext.topicsCovered.includes(t));
                const nextTopic = remaining.length > 0 ? remaining[0].replace('_', ' ') : 'finalizing the document';

                await this.vapi.start('55bd93be-541f-4870-ae3e-0c97763c12b3', {
                    firstMessage: "Welcome back! Let's continue where we left off.",
                    model: {
                        provider: "openai",
                        model: "gpt-4o",
                        temperature: 0.7,
                        messages: [{
                            role: "system",
                            content: "You are an expert business analyst conducting a requirements gathering session through natural voice conversation.\n\nYour approach:\n- Ask one focused question at a time, 1-2 sentences max\n- Listen carefully and connect the dots — when someone refers to themselves, their team, or uses pronouns, understand who they mean from context\n- Probe for specifics when answers are vague: names, roles, numbers, timelines, priorities\n- Resolve ambiguity naturally — if something is unclear, ask a brief clarifying follow-up before moving on\n- Track dependencies between answers and confirm connections\n- Be warm and conversational but efficient\n\nIMPORTANT: This is a RESUMED session. You must continue exactly where you left off.\n\n" + context + "\n\nNEXT TOPIC TO COVER: " + nextTopic + "\n\nRules:\n- Do NOT re-ask questions already answered\n- Do NOT repeat information already gathered\n- Reference what the user already told you to show continuity\n- If there are loose ends or ambiguities from earlier answers, clarify those before moving on\n- When all topics are covered, offer to generate the final requirements document"
                        }]
                    }
                });
            } else {
                // Fresh call — but include file context if files were uploaded before starting
                const fileCtx = this.buildFileContext();
                if (fileCtx) {
                    await this.vapi.start('55bd93be-541f-4870-ae3e-0c97763c12b3', {
                        model: {
                            provider: "openai",
                            model: "gpt-3.5-turbo",
                            temperature: 0.7,
                            messages: [{
                                role: "system",
                                content: "You are an expert business analyst conducting a requirements gathering session through natural voice conversation.\n\nYour approach:\n- Ask one focused question at a time, 1-2 sentences max\n- Listen carefully and probe for specifics\n- Be warm and conversational but efficient\n\nThe client has uploaded documents before starting. Use this information as background knowledge:\n\n" + fileCtx + "\n\nIncorporate this knowledge naturally. Reference specific details when relevant but don't just read the documents aloud. Start by greeting the client and asking about their project."
                            }]
                        }
                    });
                } else {
                    await this.vapi.start('55bd93be-541f-4870-ae3e-0c97763c12b3');
                }
            }
        } catch (e) { 
            this.showError('Failed: ' + e.message); 
            this.setStatus('', 'Ready', 'Tap Start'); 
        }
    }

    toggleMute() {
        if (!this.vapi || !this.inCall) return;
        const btn = document.getElementById('muteBtn');
        
        if (!this.aiHeld) {
            // HOLD AI: interrupt AI speech, mute AI audio output, keep mic live
            this.aiHeld = true;
            
            // Interrupt any current AI speech
            try { this.vapi.say(' ', false, false); } catch(e) {}
            
            // Mute all remote audio elements (AI voice output)
            this._muteRemoteAudio(true);
            
            btn.classList.add('active');
            btn.innerHTML = '▶️ Resume AI';
            this.setStatus('muted', 'AI On Hold', 'Keep talking — AI is listening but won\'t interrupt');
        } else {
            // RESUME AI: unmute AI audio, let it respond
            this.aiHeld = false;
            this._muteRemoteAudio(false);
            btn.classList.remove('active');
            btn.innerHTML = '✋ Hold AI';
            this.setStatus('listening', 'Listening', 'AI resumed');
        }
    }
    
    _muteRemoteAudio(mute) {
        // Mute/unmute all audio elements (Vapi injects audio elements for the call)
        document.querySelectorAll('audio').forEach(a => { a.muted = mute; });
        // Also try to mute via iframe if Vapi uses one
        document.querySelectorAll('iframe').forEach(iframe => {
            try {
                iframe.contentDocument.querySelectorAll('audio').forEach(a => { a.muted = mute; });
            } catch(e) {} // cross-origin will fail silently
        });
    }

    toggleMic() {
        if (!this.vapi || !this.inCall) return;
        this.micMuted = !this.micMuted;
        this.vapi.setMuted(this.isMuted || this.micMuted);
        const btn = document.getElementById('micBtn');
        if (this.micMuted) {
            btn.classList.add('active');
            btn.innerHTML = '🔇 Unmute';
        } else {
            btn.classList.remove('active');
            btn.innerHTML = '🎤 Mute';
        }
    }

    resetMuteButtons() {
        document.getElementById('muteBtn').classList.remove('active');
        document.getElementById('muteBtn').innerHTML = '✋ Let Me Speak';
        document.getElementById('micBtn').classList.remove('active');
        document.getElementById('micBtn').innerHTML = '🎤 Mute';
    }

    async sendText() {
        const input = document.getElementById('textInput');
        const text = input.value.trim();
        if (!text) return;
        
        // Use text chat API (works with or without voice call)
        {
            this.messages.push({ role: 'user', text });
            this.addTranscriptMsg('user', text);
            
            // Show thinking state
            const thinkingMsg = this.addTranscriptMsg('ai', '💭 Thinking...');
            
            try {
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        message: text,
                        transcript: this.messages,
                        fileContents: window.fileContents || {},
                        sessionId: this.sessionId
                    })
                });
                
                if (!response.ok) {
                    throw new Error('Chat request failed');
                }
                
                const data = await response.json();
                
                // Remove thinking message and add AI response
                thinkingMsg.remove();
                this.messages.push({ role: 'ai', text: data.response });
                this.addTranscriptMsg('ai', data.response);
                
                // Save the conversation
                this.saveSession();
                
            } catch (error) {
                console.error('Chat error:', error);
                thinkingMsg.textContent = '❌ Sorry, I encountered an error. Please try again.';
                setTimeout(() => thinkingMsg.remove(), 3000);
            }
        }
        input.value = '';
    }

    addTranscriptMsg(role, text) {
        const el = document.getElementById('transcript');
        const empty = el.querySelector('.t-empty');
        if (empty) empty.remove();
        const div = document.createElement('div');
        div.className = 't-msg ' + role;
        div.innerHTML = '<div class="t-role">' + (role === 'ai' ? 'AI' : 'You') + '</div>' + text;
        el.appendChild(div);
        el.scrollTop = el.scrollHeight;
        return div;
    }

    renderTranscript() {
        const el = document.getElementById('transcript');
        el.innerHTML = '';
        if (this.messages.length === 0) {
            el.innerHTML = '<div class="t-empty">Voice transcript will appear here</div>';
            return;
        }
        
        this.messages.forEach(msg => {
            this.addTranscriptMsg(msg.role, msg.text);
        });
    }

    async refreshRequirements() {
        // Check if we have files from uploaded files if window.fileContents is empty
        let filesToAnalyze = window.fileContents || {};
        if (Object.keys(filesToAnalyze).length === 0 && this.uploadedFiles && this.uploadedFiles.length > 0) {
            filesToAnalyze = {};
            this.uploadedFiles.forEach(file => {
                if (file.extracted_text) {
                    filesToAnalyze[file.original_name] = file.extracted_text;
                }
            });
        }
        
        if (this.messages.length === 0 && Object.keys(filesToAnalyze).length === 0) {
            this.showError('No conversation or files to analyze yet');
            return;
        }
        
        const refreshBtn = document.getElementById('refreshReqBtn');
        if (refreshBtn) {
            refreshBtn.disabled = true;
            refreshBtn.innerHTML = '⏳ Analyzing...';
        }
        
        try {
            const response = await fetch('/api/analyze-session', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    transcript: this.messages,
                    fileContents: filesToAnalyze,
                    sessionId: this.sessionId,
                    projectId: this.projectId,
                    existingRequirements: this.requirements
                })
            });
            
            if (!response.ok) {
                const error = await response.text();
                throw new Error(error);
            }
            
            const analysis = await response.json();
            const newReqs = analysis.requirements || {};
            
            // Merge: keep existing requirements unchanged, append new ones
            for (const [cat, items] of Object.entries(newReqs)) {
                if (!Array.isArray(items) || items.length === 0) continue;
                if (!this.requirements[cat]) {
                    this.requirements[cat] = items;
                } else {
                    // Only add items that aren't already captured
                    const existing = new Set(this.requirements[cat].map(r => r.toLowerCase().trim()));
                    const additions = items.filter(r => !existing.has(r.toLowerCase().trim()));
                    if (additions.length > 0) {
                        this.requirements[cat] = [...this.requirements[cat], ...additions];
                    }
                }
            }
            this.renderRequirements();
            
            console.log('✅ Requirements refreshed', { 
                categories: Object.keys(this.requirements).length,
                totalReqs: Object.values(this.requirements).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0)
            });
            
        } catch (e) {
            console.error('Failed to refresh requirements:', e);
            this.showError('Failed to analyze session: ' + e.message);
        } finally {
            if (refreshBtn) {
                refreshBtn.disabled = false;
                refreshBtn.innerHTML = '🔄 Refresh Requirements';
            }
        }
    }

    // addRequirement method removed - requirements are now extracted via refreshRequirements()

    renderRequirements() {
        const emptyState = document.getElementById('emptyState');
        const container = document.getElementById('reqSections');
        
        if (!this.requirements || Object.keys(this.requirements).length === 0) {
            if (emptyState) emptyState.classList.remove('hidden');
            if (container) container.innerHTML = '';
            return;
        }
        
        if (emptyState) emptyState.classList.add('hidden');
        if (!container) return;
        
        container.innerHTML = '';
        const order = ['Project Overview', 'Stakeholders', 'Functional Requirements', 'Non-Functional Requirements', 'Constraints', 'Success Criteria', 'Business Rules'];
        const rendered = new Set();
        
        for (const cat of [...order, ...Object.keys(this.requirements)]) {
            if (rendered.has(cat)) continue;
            if (!this.requirements[cat] || !Array.isArray(this.requirements[cat]) || this.requirements[cat].length === 0) continue;
            rendered.add(cat);
            
            const section = document.createElement('div');
            section.className = 'section';
            section.innerHTML = '<h3>' + this.getCatIcon(cat) + ' ' + cat + '</h3>';
            
            this.requirements[cat].forEach((r, idx) => {
                const item = document.createElement('div');
                item.className = 'req-item';
                item.style.cssText = 'display:flex;gap:8px;align-items:flex-start;';
                
                const text = document.createElement('div');
                text.contentEditable = 'true';
                text.style.cssText = 'flex:1;outline:none;min-height:1.4em;border-bottom:1px dashed transparent;';
                text.textContent = r;
                text.addEventListener('focus', () => { text.style.borderBottomColor = '#667eea'; });
                text.addEventListener('blur', () => {
                    text.style.borderBottomColor = 'transparent';
                    const newText = text.textContent.trim();
                    if (newText && newText !== r) {
                        this.requirements[cat][idx] = newText;
                        this.saveSession();
                    } else if (!newText) {
                        // Empty — remove it
                        this.requirements[cat].splice(idx, 1);
                        this.saveSession();
                        this.renderRequirements();
                    }
                });
                
                const del = document.createElement('span');
                del.textContent = '✕';
                del.style.cssText = 'cursor:pointer;color:#ccc;font-size:11px;padding:2px 4px;flex-shrink:0;';
                del.title = 'Remove';
                del.addEventListener('mouseenter', () => { del.style.color = '#f44336'; });
                del.addEventListener('mouseleave', () => { del.style.color = '#ccc'; });
                del.addEventListener('click', () => {
                    this.requirements[cat].splice(idx, 1);
                    if (this.requirements[cat].length === 0) delete this.requirements[cat];
                    this.saveSession();
                    this.renderRequirements();
                });
                
                item.appendChild(text);
                item.appendChild(del);
                section.appendChild(item);
            });
            
            // Add requirement button
            const addBtn = document.createElement('div');
            addBtn.style.cssText = 'font-size:12px;color:#667eea;cursor:pointer;padding:6px 0;opacity:0.6;';
            addBtn.textContent = '+ Add requirement';
            addBtn.addEventListener('mouseenter', () => { addBtn.style.opacity = '1'; });
            addBtn.addEventListener('mouseleave', () => { addBtn.style.opacity = '0.6'; });
            addBtn.addEventListener('click', () => {
                this.requirements[cat].push('New requirement');
                this.saveSession();
                this.renderRequirements();
                // Focus the new item
                const items = container.querySelectorAll('.section:last-child [contenteditable]');
                const last = items[items.length - 1];
                if (last) { last.focus(); document.execCommand('selectAll'); }
            });
            section.appendChild(addBtn);
            
            container.appendChild(section);
        }
    }

    getCatIcon(cat) {
        const icons = { 
            'Project Overview': '🎯', 
            'Stakeholders': '👥', 
            'Functional Requirements': '⚙️', 
            'Non-Functional Requirements': '🛡️', 
            'Constraints': '🔒', 
            'Success Criteria': '✅',
            'Business Rules': '📋',
            'General': '📝' 
        };
        return icons[cat] || '📝';
    }

    setStatus(cls, text, detail) {
        const dot = document.getElementById('statusDot');
        if (dot) dot.className = 'status-dot ' + cls;
        const statusText = document.getElementById('statusText');
        if (statusText) statusText.textContent = text;
        const statusDetail = document.getElementById('statusDetail');
        if (statusDetail) statusDetail.textContent = detail;
    }

    showError(msg) {
        const el = document.getElementById('error');
        if (el) {
            el.textContent = msg;
            el.style.display = 'block';
            setTimeout(() => el.style.display = 'none', 5000);
        }
    }

    async handleFiles(fileList) {
        for (const file of fileList) {
            this.uploadedFiles.push(file);
            this.renderFileChip(file);
            await this.processFile(file);
        }
        document.getElementById('fileInput').value = '';
    }

    renderFileChips() {
        const fileList = document.getElementById('fileList');
        fileList.innerHTML = '';
        
        this.uploadedFiles.forEach(file => {
            this.renderFileCard(file);
        });
    }
    
    renderFileCard(file) {
        const div = document.createElement('div');
        div.className = 'file-card';
        div.id = 'file-' + (file.name || file.original_name || '').replace(/[^a-z0-9]/gi, '_');
        
        const fileName = file.name || file.original_name || 'Unknown';
        const description = file.description || '';
        const fileId = file.id;
        
        div.innerHTML = `
            <div class="file-card-header">
                <div class="file-icon">📄</div>
                <div class="file-name">${fileName}</div>
                <div class="file-actions">
                    ${file.analysis ? '<span class="analyzed-badge">✅ Analyzed</span>' : ''}
                    <span class="file-remove" onclick="voiceSession.removeFile(this,'${fileName}')">✕</span>
                </div>
            </div>
            <div class="file-description">
                <textarea placeholder="Describe how this document relates to the project..." onblur="voiceSession.updateFileDescription(${fileId}, this.value)" onchange="voiceSession.updateFileDescription(${fileId}, this.value)">${description}</textarea>
            </div>
        `;
        
        document.getElementById('fileList').appendChild(div);
    }
    
    renderFileChip(file) {
        // For backward compatibility, delegate to renderFileCard
        this.renderFileCard(file);
    }

    removeFile(el, name) {
        if (!confirm('Delete this file?')) return;
        // Find the file to get its DB id
        const file = this.uploadedFiles.find(f => (f.name || f.original_name) === name);
        if (file && file.id) {
            fetch('/api/files/' + file.id, { method: 'DELETE' }).catch(e => console.error('Delete file error:', e));
        }
        this.uploadedFiles = this.uploadedFiles.filter(f => (f.name || f.original_name) !== name);
        delete (window.fileContents || {})[name];
        el.closest('.file-card').remove();
    }
    
    async updateFileDescription(fileId, description) {
        if (!fileId) return;
        
        try {
            const response = await fetch(`/api/files/${fileId}/description`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ description })
            });
            
            if (response.ok) {
                console.log('✅ File description updated');
                // Update local file object
                const file = this.uploadedFiles.find(f => f.id === fileId);
                if (file) {
                    file.description = description;
                }
            }
        } catch (error) {
            console.error('Failed to update file description:', error);
        }
    }

    async processFile(file) {
        const proc = document.getElementById('fileProcessing');
        if (proc) {
            proc.classList.remove('hidden');
            proc.textContent = '⏳ Processing ' + file.name + '...';
        }

        try {
            // Step 1: Upload and extract text
            const formData = new FormData();
            formData.append('file', file);
            if (this.projectId) formData.append('projectId', this.projectId);
            if (this.sessionId) formData.append('sessionId', this.sessionId);
            
            const uploadRes = await fetch('/api/upload', { method: 'POST', body: formData });
            if (!uploadRes.ok) throw new Error('Upload failed');
            const uploadData = await uploadRes.json();
            const content = uploadData.content;
            
            // Store raw content
            if (!window.fileContents) window.fileContents = {};
            window.fileContents[file.name] = content;
            this.sessionContext.filesUploaded.push({ name: file.name, content: content });

            if (proc) proc.textContent = '🔍 Analyzing ' + file.name + '...';

            // Step 2: AI analysis — extract requirements silently
            const analyzeRes = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    filename: file.name, 
                    content: content,
                    projectId: this.projectId,
                    sessionId: this.sessionId
                })
            });

            if (analyzeRes.ok) {
                const analysis = await analyzeRes.json();

                // Update the file card with AI description
                if (uploadData.description || analysis.summary) {
                    const desc = uploadData.description || analysis.summary;
                    const fileId = uploadData.fileId || uploadData.id;
                    const cardId = 'file-' + file.name.replace(/[^a-z0-9]/gi, '_');
                    const card = document.getElementById(cardId);
                    if (card) {
                        const textarea = card.querySelector('textarea');
                        if (textarea && !textarea.value) textarea.value = desc;
                    }
                    // Also update the uploaded file entry
                    const uf = this.uploadedFiles.find(f => (f.name || f.original_name) === file.name);
                    if (uf) { uf.description = desc; uf.id = fileId; }
                }

                // If in a voice call, restart it so AI gets the new file context
                if (this.vapi && this.inCall) {
                    if (proc) proc.textContent = '🔄 Updating voice AI with new document...';
                    try {
                        this.vapi.stop();
                        // Wait for call to end, then restart
                        await new Promise(r => setTimeout(r, 1500));
                        await this.startCall();
                    } catch (e) {
                        console.error('Failed to restart call with file context:', e);
                    }
                }

                if (proc) proc.textContent = '✅ ' + file.name + ' analyzed and ready for requirements extraction';
            } else {
                if (proc) proc.textContent = '✅ ' + file.name + ' uploaded';
            }

            setTimeout(() => {
                if (proc) proc.classList.add('hidden');
            }, 3000);
            
        } catch (e) {
            console.error('File process error:', e);
            if (proc) {
                proc.textContent = '❌ Failed to process ' + file.name;
                setTimeout(() => proc.classList.add('hidden'), 3000);
            }
        }
    }

    resetAll() {
        if (this.vapi && this.inCall) this.vapi.stop();
        this.messages = []; 
        this.requirements = {}; 
        this.uploadedFiles = [];
        this.sessionContext = { projectName: '', topicsCovered: [], keyFacts: [], currentTopic: '', filesUploaded: [] };
        
        const reqSections = document.getElementById('reqSections');
        if (reqSections) reqSections.innerHTML = '';
        
        const emptyState = document.getElementById('emptyState');
        if (emptyState) emptyState.classList.remove('hidden');
        
        const fileList = document.getElementById('fileList');
        if (fileList) fileList.innerHTML = '';
        
        const transcript = document.getElementById('transcript');
        if (transcript) transcript.innerHTML = '<div class="t-empty">Voice transcript will appear here</div>';
        
        this.setStatus('', 'Ready', 'Start a conversation to begin');
        
        if (this.sessionId) {
            this.saveSession();
        }
    }

    buildExportDoc() {
        let doc = '# Requirements Document\n\n';
        doc += '**Generated:** ' + new Date().toLocaleString() + '\n';
        if (this.projectId) doc += '**Project ID:** ' + this.projectId + '\n';
        if (this.sessionId) doc += '**Session ID:** ' + this.sessionId + '\n';
        doc += '\n';
        
        const order = ['Project Overview', 'Stakeholders', 'Functional Requirements', 'Non-Functional Requirements', 'Constraints', 'Success Criteria', 'General'];
        const seen = new Set();
        doc += '## Requirements\n\n';
        for (const cat of [...order, ...Object.keys(this.requirements)]) {
            if (seen.has(cat) || !this.requirements[cat] || this.requirements[cat].length === 0) continue;
            seen.add(cat);
            doc += '### ' + cat + '\n\n';
            this.requirements[cat].forEach(r => doc += '- ' + r + '\n');
            doc += '\n';
        }

        if (this.uploadedFiles.length > 0) {
            doc += '## Project Assets\n\n';
            this.uploadedFiles.forEach(f => doc += '- ' + f.name + ' (' + (f.size/1024).toFixed(1) + ' KB)\n');
            doc += '\n';
        }

        doc += '## Full Transcript\n\n';
        this.messages.forEach(m => doc += '**' + (m.role === 'ai' ? 'AI' : 'You') + ':** ' + m.text + '\n\n');
        doc += '---\n*Generated by VoiceReq AI*\n';
        return doc;
    }

    async exportZip() {
        const doc = this.buildExportDoc();
        try {
            const response = await fetch('/api/export-zip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    requirementsDoc: doc,
                    projectId: this.projectId,
                    sessionId: this.sessionId
                })
            });
            if (!response.ok) throw new Error('Export failed');
            const blob = await response.blob();
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'voicereq-export-' + new Date().toISOString().split('T')[0] + '.zip';
            a.click();
        } catch (e) {
            this.showError('Zip export failed: ' + e.message);
            // Fallback to markdown only
            this.exportDoc();
        }
    }

    exportDoc() {
        const doc = this.buildExportDoc();
        const blob = new Blob([doc], { type: 'text/markdown' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'requirements-' + new Date().toISOString().split('T')[0] + '.md';
        a.click();
    }
}

// Global instance
let voiceSession;

// Initialize when page loads
window.addEventListener('load', () => {
    voiceSession = new VoiceSession();
});

// Global functions for HTML event handlers
function toggleCall() { voiceSession.toggleCall(); }
function toggleMute() { voiceSession.toggleMute(); }
function toggleMic() { voiceSession.toggleMic(); }
function sendText() { voiceSession.sendText(); }
function handleFiles(files) { voiceSession.handleFiles(files); }
function resetAll() { voiceSession.resetAll(); }
function exportZip() { voiceSession.exportZip(); }
function exportDoc() { voiceSession.exportDoc(); }
function refreshRequirements() { voiceSession.refreshRequirements(); }