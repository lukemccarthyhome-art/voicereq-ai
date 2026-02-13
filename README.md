# Morti Projects - Voice-Powered Requirements Gathering

An AI-powered web application that gathers software requirements through natural voice conversations.

## Features

- 🎙️ **Voice-First Interface**: Speak naturally with AI assistant
- 🤖 **AI-Guided Conversation**: Structured requirements gathering flow
- 📝 **Real-time Transcription**: See conversation as it happens
- 🔊 **Natural AI Voice**: ElevenLabs text-to-speech integration
- 📄 **Document Export**: Generate professional requirements documents
- 🎯 **Comprehensive Coverage**: Project goals, stakeholders, functional/non-functional requirements, constraints

## Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript (Web Speech API)
- **Backend**: Node.js, Express.js
- **AI**: Anthropic Claude for conversational logic
- **Voice**: ElevenLabs for text-to-speech, Web Speech API for speech-to-text
- **Styling**: Modern CSS with responsive design

## Quick Start

### Prerequisites

- Node.js (v16 or higher)
- Chrome or Edge browser (for Web Speech API)
- Anthropic API key
- Microphone access

### Installation

1. **Clone and setup:**
   ```bash
   cd voicereq-app
   npm install
   ```

2. **Configure API key:**
   ```bash
   export ANTHROPIC_API_KEY="your_anthropic_api_key_here"
   ```
   
   Or create a `.env` file:
   ```bash
   cp .env.example .env
   # Edit .env and add your Anthropic API key
   ```

3. **Start the server:**
   ```bash
   npm start
   ```

4. **Open the app:**
   Navigate to `http://localhost:3000`

## Usage

1. **Allow microphone access** when prompted by your browser
2. **Click "Start Conversation"** to begin
3. **Speak naturally** when the AI asks questions
4. **Follow the guided flow** through all requirement areas:
   - Project basics (name, description, goals)
   - Stakeholders identification
   - Functional requirements
   - Non-functional requirements (performance, security, etc.)
   - Constraints (budget, timeline, technology)
   - Success criteria
5. **Export document** when conversation is complete

## Browser Compatibility

- ✅ Chrome (recommended)
- ✅ Edge
- ✅ Safari (limited Web Speech API support)
- ❌ Firefox (no Web Speech API support)

## API Configuration

### Anthropic API
- Model: Claude 3 Sonnet
- Required environment variable: `ANTHROPIC_API_KEY`
- Used for conversational AI logic and document generation

### ElevenLabs API
- Voice: Bella (default, natural-sounding female voice)
- API key: Hardcoded in server.js for demo (move to env in production)
- Used for AI text-to-speech output

## Architecture

```
Frontend (Browser)
├── Web Speech API (STT)
├── Audio playback (TTS)
└── Modern responsive UI

Backend (Node.js)
├── Express server (port 3000)
├── Anthropic API integration
├── ElevenLabs API integration
└── Static file serving

APIs
├── Anthropic Claude (conversational AI)
└── ElevenLabs (text-to-speech)
```

## File Structure

```
voicereq-app/
├── server.js              # Node.js Express server
├── package.json           # Dependencies and scripts
├── .env.example          # Environment variables template
├── README.md             # This file
└── public/               # Frontend files
    ├── index.html        # Main app interface
    ├── styles.css        # CSS styling
    └── app.js            # JavaScript application logic
```

## Troubleshooting

### Common Issues

**"Speech recognition not supported"**
- Use Chrome or Edge browser
- Ensure HTTPS connection (required for Web Speech API)

**"Microphone access denied"**
- Allow microphone permissions in browser
- Check system microphone settings
- Refresh page after granting permissions

**"Anthropic API key not configured"**
- Set ANTHROPIC_API_KEY environment variable
- Check .env file configuration
- Restart server after setting environment variables

**Audio not playing**
- Check browser audio settings
- Ensure speakers/headphones are connected
- Try clicking on the page before starting (browsers require user interaction for audio)

### Debug Mode

Check browser console (F12) for detailed logs and error messages.

## Security Notes

- ElevenLabs API key is currently hardcoded for demo purposes
- In production, move all API keys to environment variables
- Consider implementing rate limiting and user authentication
- Voice data is processed in real-time and not stored

## License

MIT License - feel free to modify and use for your projects.