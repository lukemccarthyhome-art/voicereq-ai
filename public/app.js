class VoiceReqAI {
  constructor() {
    this.ws = null;
    this.audioContext = null;
    this.mediaStream = null;
    this.audioWorkletNode = null;
    this.isConnected = false;
    this.isListening = false;
    this.isSpeaking = false;
    this.conversationHistory = [];
    this.currentTranscript = '';

    // UI elements
    this.statusIcon = document.getElementById('statusIcon');
    this.statusText = document.getElementById('statusText');
    this.statusDetails = document.getElementById('statusDetails');
    this.transcript = document.getElementById('transcript');
    this.startBtn = document.getElementById('startBtn');
    this.stopBtn = document.getElementById('stopBtn');
    this.exportBtn = document.getElementById('exportBtn');
    this.resetBtn = document.getElementById('resetBtn');
    this.errorPanel = document.getElementById('errorPanel');
    this.errorText = document.getElementById('errorText');
    this.loadingOverlay = document.getElementById('loadingOverlay');

    this.bindEvents();
  }

  bindEvents() {
    this.startBtn.addEventListener('click', () => this.startConversation());
    this.stopBtn.addEventListener('click', () => this.stopConversation());
    this.exportBtn.addEventListener('click', () => this.exportDocument());
    this.resetBtn.addEventListener('click', () => this.resetConversation());
  }

  async startConversation() {
    try {
      this.showLoading('Initializing audio...');
      
      // Initialize AudioContext on user gesture (required for iOS)
      await this.initializeAudio();
      
      // Connect to WebSocket
      await this.connectWebSocket();
      
      this.hideLoading();
      this.updateUI('connected');
      
    } catch (error) {
      console.error('Error starting conversation:', error);
      this.showError('Failed to start conversation: ' + error.message);
      this.hideLoading();
    }
  }

  async initializeAudio() {
    if (this.audioContext) {
      return; // Already initialized
    }

    // Create AudioContext
    this.audioContext = new (window.AudioContext || window.webkitAudioContext)({
      sampleRate: 24000, // OpenAI Realtime API expects 24kHz
    });

    // Resume context if suspended (iOS requirement)
    if (this.audioContext.state === 'suspended') {
      await this.audioContext.resume();
    }

    // Get microphone access
    this.mediaStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        channelCount: 1,
        sampleRate: 24000,
        sampleSize: 16,
        volume: 1.0
      }
    });

    // Create audio processing worklet
    await this.setupAudioWorklet();
  }

  async setupAudioWorklet() {
    // Create a ScriptProcessorNode for audio processing (more compatible than AudioWorklet)
    const source = this.audioContext.createMediaStreamSource(this.mediaStream);
    const processor = this.audioContext.createScriptProcessor(4096, 1, 1);

    processor.onaudioprocess = (event) => {
      if (!this.isListening) return;

      const inputData = event.inputBuffer.getChannelData(0);
      
      // Convert float32 to int16 PCM
      const pcm16Buffer = new Int16Array(inputData.length);
      for (let i = 0; i < inputData.length; i++) {
        pcm16Buffer[i] = Math.max(-32768, Math.min(32767, inputData[i] * 32768));
      }

      // Send audio to server
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        const audioEvent = {
          type: 'input_audio_buffer.append',
          audio: this.arrayBufferToBase64(pcm16Buffer.buffer)
        };
        this.ws.send(JSON.stringify(audioEvent));
      }
    };

    source.connect(processor);
    processor.connect(this.audioContext.destination);
    this.audioWorkletNode = processor;
  }

  connectWebSocket() {
    return new Promise((resolve, reject) => {
      const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${location.host}/ws`;
      
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('Connected to server WebSocket');
        // Request connection to OpenAI
        this.ws.send(JSON.stringify({
          type: 'session.connect'
        }));
      };

      this.ws.onmessage = (event) => {
        this.handleWebSocketMessage(JSON.parse(event.data));
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        reject(new Error('WebSocket connection failed'));
      };

      this.ws.onclose = () => {
        console.log('WebSocket connection closed');
        this.isConnected = false;
        this.updateUI('disconnected');
      };

      // Set up connection timeout
      setTimeout(() => {
        if (!this.isConnected) {
          reject(new Error('Connection timeout'));
        } else {
          resolve();
        }
      }, 10000);
    });
  }

  handleWebSocketMessage(message) {
    console.log('Received message:', message.type);

    switch (message.type) {
      case 'session.ready':
        this.isConnected = true;
        this.startListening();
        break;

      case 'input_audio_buffer.speech_started':
        this.updateUI('user_speaking');
        break;

      case 'input_audio_buffer.speech_stopped':
        // Server VAD handles committing automatically, don't manually commit
        this.updateUI('processing');
        break;

      case 'conversation.item.input_audio_transcription.completed':
        this.addMessage('user', message.transcript);
        break;

      case 'response.audio.delta':
        this.playAudioChunk(message.delta);
        break;

      case 'response.audio.done':
        this.updateUI('listening');
        break;

      case 'response.text.delta':
        // Update AI response text as it comes in
        this.updateCurrentAIResponse(message.delta);
        break;

      case 'response.text.done':
        this.finalizeAIResponse(message.text);
        break;

      case 'response.done':
        this.updateUI('listening');
        break;

      case 'error':
        console.error('OpenAI error:', message.error);
        this.showError('OpenAI error: ' + message.error.message);
        break;
    }
  }

  startListening() {
    this.isListening = true;
    this.updateUI('listening');
  }

  stopConversation() {
    this.isListening = false;
    
    if (this.ws) {
      this.ws.close();
    }
    
    if (this.mediaStream) {
      this.mediaStream.getTracks().forEach(track => track.stop());
      this.mediaStream = null;
    }

    if (this.audioWorkletNode) {
      this.audioWorkletNode.disconnect();
      this.audioWorkletNode = null;
    }

    this.updateUI('stopped');
  }

  async playAudioChunk(audioBase64) {
    if (!this.audioContext || !audioBase64) return;

    try {
      // Decode base64 to array buffer
      const binaryString = atob(audioBase64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      // Convert PCM16 to Float32 for Web Audio API
      const int16Array = new Int16Array(bytes.buffer);
      const float32Array = new Float32Array(int16Array.length);
      for (let i = 0; i < int16Array.length; i++) {
        float32Array[i] = int16Array[i] / 32768.0;
      }

      // Create audio buffer and play
      const audioBuffer = this.audioContext.createBuffer(1, float32Array.length, 24000);
      audioBuffer.getChannelData(0).set(float32Array);

      const source = this.audioContext.createBufferSource();
      source.buffer = audioBuffer;
      source.connect(this.audioContext.destination);
      source.start();

      if (!this.isSpeaking) {
        this.isSpeaking = true;
        this.updateUI('ai_speaking');
      }

      // Reset speaking state after audio finishes
      source.onended = () => {
        // Note: This will be called for each chunk, so we don't immediately reset
        setTimeout(() => {
          this.isSpeaking = false;
        }, 100);
      };

    } catch (error) {
      console.error('Error playing audio chunk:', error);
    }
  }

  addMessage(role, content) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${role}-message`;
    
    const contentDiv = document.createElement('div');
    contentDiv.className = 'message-content';
    contentDiv.innerHTML = `<p><strong>${role === 'user' ? 'You' : 'AI Assistant'}:</strong> ${content}</p>`;
    
    messageDiv.appendChild(contentDiv);
    this.transcript.appendChild(messageDiv);
    
    // Scroll to bottom
    this.transcript.scrollTop = this.transcript.scrollHeight;
    
    // Store in conversation history
    this.conversationHistory.push({ role, content });
    
    // Show export button if we have some conversation
    if (this.conversationHistory.length > 2) {
      this.exportBtn.style.display = 'inline-block';
    }
  }

  updateCurrentAIResponse(delta) {
    // Update the current AI response as it comes in
    let lastMessage = this.transcript.lastElementChild;
    if (!lastMessage || !lastMessage.classList.contains('ai-message')) {
      // Create new AI message
      const messageDiv = document.createElement('div');
      messageDiv.className = 'message ai-message';
      
      const contentDiv = document.createElement('div');
      contentDiv.className = 'message-content';
      contentDiv.innerHTML = '<p><strong>AI Assistant:</strong> <span class="response-text"></span></p>';
      
      messageDiv.appendChild(contentDiv);
      this.transcript.appendChild(messageDiv);
      lastMessage = messageDiv;
    }
    
    const responseSpan = lastMessage.querySelector('.response-text');
    if (responseSpan) {
      responseSpan.textContent += delta;
    }
    
    this.transcript.scrollTop = this.transcript.scrollHeight;
  }

  finalizeAIResponse(fullText) {
    // Add to conversation history
    this.conversationHistory.push({ role: 'assistant', content: fullText });
    
    // Show export button if we have some conversation
    if (this.conversationHistory.length > 2) {
      this.exportBtn.style.display = 'inline-block';
    }
  }

  updateUI(state) {
    switch (state) {
      case 'connecting':
        this.statusIcon.textContent = '🔄';
        this.statusText.textContent = 'Connecting...';
        this.statusDetails.textContent = 'Establishing connection to AI assistant';
        break;
        
      case 'connected':
        this.statusIcon.textContent = '✅';
        this.statusText.textContent = 'Connected';
        this.statusDetails.textContent = 'Ready to start conversation';
        this.startBtn.style.display = 'none';
        this.stopBtn.style.display = 'inline-block';
        break;
        
      case 'listening':
        this.statusIcon.textContent = '🎤';
        this.statusText.textContent = 'Listening';
        this.statusDetails.textContent = 'Speak now - I\'m listening for your requirements';
        break;
        
      case 'user_speaking':
        this.statusIcon.textContent = '👤';
        this.statusText.textContent = 'You\'re speaking';
        this.statusDetails.textContent = 'Processing your voice input...';
        break;
        
      case 'processing':
        this.statusIcon.textContent = '🤔';
        this.statusText.textContent = 'Thinking';
        this.statusDetails.textContent = 'AI is processing your input...';
        break;
        
      case 'ai_speaking':
        this.statusIcon.textContent = '🗣️';
        this.statusText.textContent = 'AI Speaking';
        this.statusDetails.textContent = 'AI assistant is responding...';
        break;
        
      case 'stopped':
        this.statusIcon.textContent = '⏹️';
        this.statusText.textContent = 'Stopped';
        this.statusDetails.textContent = 'Conversation ended';
        this.startBtn.style.display = 'inline-block';
        this.stopBtn.style.display = 'none';
        break;
        
      case 'disconnected':
        this.statusIcon.textContent = '🔌';
        this.statusText.textContent = 'Disconnected';
        this.statusDetails.textContent = 'Connection lost';
        this.startBtn.style.display = 'inline-block';
        this.stopBtn.style.display = 'none';
        break;
    }
  }

  async exportDocument() {
    if (this.conversationHistory.length === 0) {
      this.showError('No conversation to export');
      return;
    }

    try {
      this.showLoading('Generating requirements document...');

      // Create conversation summary for document generation
      const conversationText = this.conversationHistory
        .map(msg => `${msg.role === 'user' ? 'User' : 'AI Assistant'}: ${msg.content}`)
        .join('\n\n');

      // For now, create a simple document. In a real implementation,
      // you might want to send this to an API to generate a formatted document
      const document = `# Software Requirements Document
      
## Generated from Morti Projects Conversation

**Date:** ${new Date().toLocaleDateString()}
**Time:** ${new Date().toLocaleTimeString()}

## Conversation Transcript

${conversationText}

## Summary

This document was automatically generated from a voice conversation with Morti Projects.
The conversation covered project requirements gathering through natural dialogue.

---

*Generated by Morti Projects - Voice-Powered Requirements Gathering*
`;

      // Create and download the file
      const blob = new Blob([document], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `requirements-${new Date().toISOString().split('T')[0]}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      this.hideLoading();
      this.showError('Requirements document exported successfully!', false);

    } catch (error) {
      console.error('Error exporting document:', error);
      this.showError('Failed to export document: ' + error.message);
      this.hideLoading();
    }
  }

  resetConversation() {
    this.stopConversation();
    this.conversationHistory = [];
    this.transcript.innerHTML = `
      <div class="message welcome-message">
        <div class="message-content">
          <p><strong>Welcome to Morti Projects!</strong></p>
          <p>I'm your AI requirements gathering assistant. I'll help you capture comprehensive software requirements through natural conversation.</p>
          <p>We'll cover project goals, stakeholders, functional requirements, constraints, and more. Ready to begin?</p>
        </div>
      </div>
    `;
    this.exportBtn.style.display = 'none';
    this.updateUI('disconnected');
  }

  showError(message, isError = true) {
    this.errorText.textContent = message;
    this.errorPanel.style.display = 'block';
    this.errorPanel.className = `error-panel ${isError ? 'error' : 'success'}`;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
      this.hideError();
    }, 5000);
  }

  hideError() {
    this.errorPanel.style.display = 'none';
  }

  showLoading(message = 'Loading...') {
    document.getElementById('loadingText').textContent = message;
    this.loadingOverlay.style.display = 'flex';
  }

  hideLoading() {
    this.loadingOverlay.style.display = 'none';
  }

  arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  window.voiceReqAI = new VoiceReqAI();
});

// Legacy function support for HTML onclick handlers
function startConversation() {
  if (window.voiceReqAI) {
    window.voiceReqAI.startConversation();
  }
}

function stopListening() {
  if (window.voiceReqAI) {
    window.voiceReqAI.stopConversation();
  }
}

function exportDocument() {
  if (window.voiceReqAI) {
    window.voiceReqAI.exportDocument();
  }
}

function resetConversation() {
  if (window.voiceReqAI) {
    window.voiceReqAI.resetConversation();
  }
}

function hideError() {
  if (window.voiceReqAI) {
    window.voiceReqAI.hideError();
  }
}