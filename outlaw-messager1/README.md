# 🤠 Outlaw Telegraph - Advanced Secure Messaging Platform

[![Deploy to Replit](https://replit.com/badge/github/your-username/outlaw-telegraph)](https://replit.com/new/github/your-username/outlaw-telegraph)

## 🌟 Features

- **Zero-Knowledge Encryption**: End-to-end encrypted messaging with RSA-2048
- **Voice Biometric Authentication**: Dual verification with speech-to-text + voiceprint matching
- **Blockchain Verification**: Message integrity protection with SHA-256 hashes
- **Steganography**: Hide messages within images using LSB encoding
- **Real-time Messaging**: Socket.IO powered instant communication
- **Self-Destructing Messages**: Automatic message deletion
- **Western Theme**: Authentic Wild West aesthetic

## 🚀 Quick Start

### Option 1: Run on Replit (Recommended)
1. Click the "Deploy to Replit" button above
2. Wait for dependencies to install
3. Click "Run" 
4. Open the web preview
5. Register your outlaw account!

### Option 2: Local Development
```bash
# Clone the repository
git clone https://github.com/your-username/outlaw-telegraph.git
cd outlaw-telegraph

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

Visit `http://localhost:5000` in your browser.

## 🔧 Environment Setup

### Required Dependencies
- Python 3.11+
- Flask 3.1.2+
- All dependencies listed in `pyproject.toml`

### Audio Requirements
- Microphone access for voice authentication
- Modern browser with WebRTC support
- Quiet environment for optimal voice recognition

## 🎮 How to Use

### 1. Traditional Registration
- Visit `/register`
- Create username, email, password
- Automatic RSA key generation

### 2. Voice Profile Setup
- Go to `/voice_register` (after login)
- Upload 15+ second voice sample
- System creates biometric voiceprint

### 3. Voice Authentication Login
- Visit `/voice_login`
- Enter username
- Speak the generated challenge phrase
- Dual verification: phrase + voiceprint

### 4. Secure Messaging
- Start private chats with other users
- Send encrypted text, files, images
- Use steganography to hide messages
- Set self-destruct timers

## 🔐 Security Features

### Zero-Knowledge Encryption
- **RSA-2048**: Public key cryptography
- **AES Hybrid**: Efficient large message encryption
- **Client-Side Keys**: Private keys never stored on server
- **Per-Recipient**: Individual encryption for each user

### Voice Biometrics
- **MFCC Features**: 13-coefficient voice fingerprinting
- **Cosine Similarity**: 70% threshold for authentication
- **Challenge Phrases**: Anti-replay protection
- **Dual Verification**: Speech + biometric matching

### Blockchain Integration
- **SHA-256 Hashing**: Message integrity verification
- **Tamper Detection**: Cryptographic audit trail
- **Block Linking**: Immutable communication record

### Steganography
- **LSB Encoding**: Hide messages in image pixels
- **PNG Support**: Lossless format preservation
- **Covert Channels**: Invisible communication

## 🏗️ Technical Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Flask Backend  │    │   Database      │
│   - HTML/JS     │◄──►│   - Socket.IO    │◄──►│   - SQLite      │
│   - WebRTC      │    │   - Cryptography │    │   - Encrypted   │
│   - Audio API   │    │   - Voice Auth   │    │   - Messages    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🌐 Deployment Options

### Production Deployment
See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed production setup including:
- Heroku deployment
- DigitalOcean setup
- AWS EC2 configuration
- Docker containerization
- HTTPS/SSL setup

## 🛡️ Security Considerations

### Production Security
- Change default secret keys
- Use HTTPS in production
- Implement rate limiting
- Add CSRF protection
- Use production database (PostgreSQL)
- Enable proper logging

### Privacy Features
- No plain text message storage
- Minimal metadata collection
- Self-destructing capabilities
- End-to-end encryption

## 🔧 Configuration

### Environment Variables
```bash
FLASK_SECRET_KEY=your-super-secret-key-change-in-production
DATABASE_URL=sqlite:///messenger.db  # or PostgreSQL URL
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=104857600  # 100MB
```

### Voice Authentication Settings
```python
# Challenge phrases (customizable)
CHALLENGE_PHRASES = [
    "The quick brown fox jumps over the lazy dog",
    "My voice is my password",
    # Add your own phrases...
]

# Voice matching threshold (0.0-1.0)
VOICE_SIMILARITY_THRESHOLD = 0.7
```

## 🐛 Troubleshooting

### Common Issues
1. **Microphone not working**: Check browser permissions
2. **Voice authentication failing**: Ensure quiet environment, speak clearly
3. **File uploads failing**: Check file size limits and formats
4. **Messages not encrypting**: Verify user has public key generated

### Debug Mode
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## 🎯 Roadmap

- [ ] Mobile app development
- [ ] Video calling integration
- [ ] Advanced biometrics (facial recognition)
- [ ] Real blockchain integration
- [ ] Post-quantum cryptography
- [ ] Multi-language support

## 🏆 Acknowledgments

- Flask community for excellent web framework
- Librosa team for audio processing capabilities
- Cryptography library maintainers
- Socket.IO for real-time communication

---

**Built with ❤️ and advanced cryptography for the privacy-conscious digital frontier.**

## 📞 Support

- 📧 Email: your-email@example.com
- 🐛 Issues: [GitHub Issues](https://github.com/your-username/outlaw-telegraph/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/your-username/outlaw-telegraph/discussions)

---

*"In the digital Wild West, your privacy is your most valuable asset. Ride safe, partner."* 🤠