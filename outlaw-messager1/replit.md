# Outlaw Telegraph - Secure Messaging Application

## Overview

Outlaw Telegraph is a Flask-based secure messaging application featuring real-time chat capabilities, biometric voice authentication, and steganographic image messaging. The application uses a Western outlaw theme and provides multiple layers of security including traditional password authentication, voice biometrics, and encrypted message storage. It supports both individual and group conversations with file sharing capabilities.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Template Engine**: Jinja2 templating with Flask for server-side rendering
- **UI Framework**: Bootstrap 5.1.3 for responsive design with custom Western-themed styling
- **Real-time Communication**: Socket.IO client for bidirectional communication
- **Interactive Elements**: JavaScript for form handling, file uploads, and WebSocket management
- **Design Pattern**: Traditional multi-page application with themed CSS using CSS custom properties for consistent color schemes

### Backend Architecture
- **Web Framework**: Flask as the primary web server with modular route handling
- **Real-time Engine**: Flask-SocketIO for WebSocket-based real-time messaging with room-based chat organization
- **Authentication System**: 
  - Traditional username/password with Werkzeug password hashing
  - Biometric voice authentication using audio processing and machine learning
  - Session-based authentication with Flask sessions
- **Security Layer**: Cryptography.Fernet for end-to-end message encryption
- **File Processing**: 
  - Audio processing with librosa and pydub for voice authentication
  - Image processing with PIL for steganography features
  - Speech recognition with speech_recognition library

### Data Storage Solutions
- **Primary Database**: SQLite with SQLAlchemy ORM for user accounts, chat history, and metadata
- **File Storage**: Local file system storage in uploads directory with secure filename handling
- **Session Storage**: Flask server-side sessions for authentication state
- **Biometric Data**: Processed voiceprints stored as mathematical models (original audio discarded for privacy)

### Authentication and Authorization Mechanisms
- **Dual Authentication Modes**: 
  - Traditional password-based login
  - Biometric voice authentication with challenge-response system
- **Voice Authentication Process**:
  - Initial enrollment: MP3 upload converted to 16-bit PCM WAV for voiceprint creation
  - Login verification: Random challenge phrases with dual verification (speech-to-text + voice pattern matching)
- **Session Management**: Flask session handling with secure session keys
- **Authorization**: Role-based access with user ownership validation for messages and files

### Message Security Architecture
- **End-to-End Encryption**: All messages encrypted using Fernet symmetric encryption
- **Steganography Features**: LSB (Least Significant Bit) hiding of messages within images
- **Secure File Handling**: File type validation, size limits, and secure filename generation
- **Privacy Protection**: Original voice samples destroyed after voiceprint extraction

### Real-time Communication Design
- **WebSocket Architecture**: Socket.IO rooms for organizing conversations
- **Event-Driven System**: Real-time message broadcasting with user presence indicators
- **Scalability Pattern**: Room-based message routing for efficient group communication

## External Dependencies

### Core Framework Dependencies
- **Flask**: Web application framework with SQLAlchemy extension for database operations
- **Flask-SocketIO**: WebSocket implementation for real-time bidirectional communication
- **Werkzeug**: WSGI utilities for password hashing and secure file handling

### Security and Cryptography
- **Cryptography**: Fernet symmetric encryption for message protection
- **Environment Variables**: Encryption keys managed through environment variables for security

### Audio Processing and Voice Authentication
- **librosa**: Audio analysis and feature extraction for voiceprint generation
- **pydub**: Audio format conversion and manipulation
- **speech_recognition**: Speech-to-text conversion for challenge phrase verification
- **numpy**: Numerical operations for audio signal processing
- **scikit-learn**: Cosine similarity calculations for voice pattern matching

### Image Processing and Steganography
- **PIL (Pillow)**: Image processing for steganographic message hiding and revelation
- **base64**: Image encoding for web transmission

### Frontend Resources (CDN)
- **Bootstrap 5.1.3**: UI framework for responsive design
- **Font Awesome 6.0.0**: Icon library for UI elements
- **Google Fonts**: Custom typography (Creepster, Rye, Smokum fonts for Western theme)
- **Socket.IO Client 4.0.0**: Client-side WebSocket communication

### Development and Deployment
- **Python Standard Libraries**: os, json, datetime, threading, time for system operations
- **File Upload Handling**: Configurable upload limits and type validation
- **Cross-Origin Resource Sharing**: CORS support for WebSocket connections

### Audio Format Requirements
- **Target Format**: 16-bit PCM, 16,000 Hz, mono channel for voice authentication
- **Supported Formats**: WAV, MP3, OGG, FLAC for user uploads
- **Conversion Pipeline**: Automatic format standardization for biometric processing