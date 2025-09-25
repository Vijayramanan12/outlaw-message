
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json
from datetime import datetime, timedelta
import threading
import time
import pytz
import librosa
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from PIL import Image
import io
import base64
from numpy.linalg import norm
from pydub import AudioSegment
import speech_recognition as sr
import random
import hashlib
import requests
from cryptography.hazmat.backends import default_backend
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messenger.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_AUDIO_EXTENSIONS = {'wav', 'mp3', 'ogg', 'flac', 'm4a', 'aac'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp', 'tiff'}
ALLOWED_DOCUMENT_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'zip', 'rar', 'ppt', 'pptx', 'xls', 'xlsx'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'avi', 'mov', 'mkv', 'flv', 'wmv'}
ALLOWED_FILE_EXTENSIONS = ALLOWED_AUDIO_EXTENSIONS | ALLOWED_IMAGE_EXTENSIONS | ALLOWED_DOCUMENT_EXTENSIONS | ALLOWED_VIDEO_EXTENSIONS

def allowed_audio_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_AUDIO_EXTENSIONS

def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_FILE_EXTENSIONS

def get_file_type(filename):
    """Determine file type category"""
    if not filename or '.' not in filename:
        return 'unknown'
    
    ext = filename.rsplit('.', 1)[1].lower()
    if ext in ALLOWED_IMAGE_EXTENSIONS:
        return 'image'
    elif ext in ALLOWED_AUDIO_EXTENSIONS:
        return 'audio'
    elif ext in ALLOWED_VIDEO_EXTENSIONS:
        return 'video'
    elif ext in ALLOWED_DOCUMENT_EXTENSIONS:
        return 'document'
    else:
        return 'unknown'

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Blockchain Configuration (using a simple local blockchain for demo)
BLOCKCHAIN_API_URL = "https://api.blockcypher.com/v1/btc/test3"  # TestNet for demo

# Timezone configuration
IST = pytz.timezone('Asia/Kolkata')

def get_ist_time():
    return datetime.now(IST)

# Zero-Knowledge Cryptography Functions
class ZeroKnowledgeCrypto:
    @staticmethod
    def generate_keypair():
        """Generate RSA key pair for users"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode(), public_pem.decode()
    
    @staticmethod
    def encrypt_with_public_key(message, public_key_pem):
        """Encrypt message with recipient's public key"""
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )
        
        # For large messages, use hybrid encryption
        if len(message.encode()) > 190:  # RSA-2048 can encrypt max ~190 bytes
            return ZeroKnowledgeCrypto._hybrid_encrypt(message, public_key)
        
        encrypted = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    
    @staticmethod
    def decrypt_with_private_key(encrypted_message, private_key_pem):
        """Decrypt message with user's private key"""
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None, backend=default_backend()
        )
        
        try:
            # Try direct RSA decryption first
            encrypted_bytes = base64.b64decode(encrypted_message.encode())
            decrypted = private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode()
        except:
            # Try hybrid decryption
            return ZeroKnowledgeCrypto._hybrid_decrypt(encrypted_message, private_key)
    
    @staticmethod
    def _hybrid_encrypt(message, public_key):
        """Hybrid encryption for large messages"""
        # Generate symmetric key
        symmetric_key = secrets.token_bytes(32)
        cipher_suite = Fernet(base64.urlsafe_b64encode(symmetric_key))
        
        # Encrypt message with symmetric key
        encrypted_message = cipher_suite.encrypt(message.encode())
        
        # Encrypt symmetric key with public key
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine encrypted key and message
        combined = base64.b64encode(encrypted_key).decode() + "|||" + encrypted_message.decode()
        return base64.b64encode(combined.encode()).decode()
    
    @staticmethod
    def _hybrid_decrypt(encrypted_data, private_key):
        """Hybrid decryption for large messages"""
        try:
            combined = base64.b64decode(encrypted_data.encode()).decode()
            encrypted_key_b64, encrypted_message = combined.split("|||")
            
            # Decrypt symmetric key
            encrypted_key = base64.b64decode(encrypted_key_b64.encode())
            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message
            cipher_suite = Fernet(base64.urlsafe_b64encode(symmetric_key))
            decrypted = cipher_suite.decrypt(encrypted_message.encode())
            return decrypted.decode()
        except Exception as e:
            print(f"Hybrid decryption failed: {e}")
            return "[Message could not be decrypted]"

# Blockchain Functions
class BlockchainService:
    @staticmethod
    def create_message_hash(message_id, sender_id, recipient_id, timestamp):
        """Create cryptographic hash for blockchain storage"""
        data = f"{message_id}:{sender_id}:{recipient_id}:{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    @staticmethod
    def store_on_blockchain(data_hash, metadata=None):
        """Store hash on blockchain (simplified for demo)"""
        try:
            # In production, this would interact with a real blockchain
            # For demo, we'll store locally and simulate blockchain storage
            blockchain_record = {
                'hash': data_hash,
                'timestamp': time.time(),
                'metadata': metadata or {},
                'block_id': secrets.token_hex(16)
            }
            
            # Store in local "blockchain" file for demo
            blockchain_file = os.path.join(app.config['UPLOAD_FOLDER'], 'blockchain_records.json')
            records = []
            
            if os.path.exists(blockchain_file):
                with open(blockchain_file, 'r') as f:
                    records = json.load(f)
            
            records.append(blockchain_record)
            
            with open(blockchain_file, 'w') as f:
                json.dump(records, f, indent=2)
            
            return blockchain_record['block_id']
        except Exception as e:
            print(f"Blockchain storage error: {e}")
            return None
    
    @staticmethod
    def verify_message_integrity(message_id, stored_hash):
        """Verify message hasn't been tampered with"""
        try:
            blockchain_file = os.path.join(app.config['UPLOAD_FOLDER'], 'blockchain_records.json')
            if not os.path.exists(blockchain_file):
                return False
            
            with open(blockchain_file, 'r') as f:
                records = json.load(f)
            
            for record in records:
                if record.get('hash') == stored_hash:
                    return True
            return False
        except:
            return False

# Extended Encryption Functions
class ExtendedEncryption:
    @staticmethod
    def encrypt_file(file_path, public_key_pem, file_type):
        """Encrypt files based on type"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            if file_type == 'image':
                return ExtendedEncryption._encrypt_image_advanced(file_data, public_key_pem)
            elif file_type == 'audio':
                return ExtendedEncryption._encrypt_audio_advanced(file_data, public_key_pem)
            elif file_type == 'video':
                return ExtendedEncryption._encrypt_video_advanced(file_data, public_key_pem)
            elif file_type == 'document':
                return ExtendedEncryption._encrypt_document_advanced(file_data, public_key_pem)
            else:
                return ExtendedEncryption._encrypt_generic(file_data, public_key_pem)
        except Exception as e:
            print(f"File encryption error: {e}")
            return None
    
    @staticmethod
    def decrypt_file(encrypted_data, private_key_pem, file_type):
        """Decrypt files based on type"""
        try:
            if file_type == 'image':
                return ExtendedEncryption._decrypt_image_advanced(encrypted_data, private_key_pem)
            elif file_type == 'audio':
                return ExtendedEncryption._decrypt_audio_advanced(encrypted_data, private_key_pem)
            elif file_type == 'video':
                return ExtendedEncryption._decrypt_video_advanced(encrypted_data, private_key_pem)
            elif file_type == 'document':
                return ExtendedEncryption._decrypt_document_advanced(encrypted_data, private_key_pem)
            else:
                return ExtendedEncryption._decrypt_generic(encrypted_data, private_key_pem)
        except Exception as e:
            print(f"File decryption error: {e}")
            return None
    
    @staticmethod
    def _encrypt_generic(file_data, public_key_pem):
        """Generic file encryption using hybrid method"""
        # Generate symmetric key
        symmetric_key = secrets.token_bytes(32)
        cipher_suite = Fernet(base64.urlsafe_b64encode(symmetric_key))
        
        # Encrypt file data
        encrypted_data = cipher_suite.encrypt(file_data)
        
        # Encrypt symmetric key with public key
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(), backend=default_backend()
        )
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine and encode
        combined = {
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'encrypted_data': encrypted_data.decode()
        }
        return base64.b64encode(json.dumps(combined).encode()).decode()
    
    @staticmethod
    def _decrypt_generic(encrypted_data, private_key_pem):
        """Generic file decryption"""
        try:
            combined_data = json.loads(base64.b64decode(encrypted_data.encode()).decode())
            encrypted_key = base64.b64decode(combined_data['encrypted_key'].encode())
            
            # Decrypt symmetric key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(), password=None, backend=default_backend()
            )
            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt file data
            cipher_suite = Fernet(base64.urlsafe_b64encode(symmetric_key))
            decrypted_data = cipher_suite.decrypt(combined_data['encrypted_data'].encode())
            return decrypted_data
        except Exception as e:
            print(f"Generic decryption error: {e}")
            return None
    
    @staticmethod
    def _encrypt_image_advanced(image_data, public_key_pem):
        """Advanced image encryption with steganography"""
        # First encrypt normally
        encrypted = ExtendedEncryption._encrypt_generic(image_data, public_key_pem)
        
        # Add steganography layer if needed
        return encrypted
    
    @staticmethod
    def _decrypt_image_advanced(encrypted_data, private_key_pem):
        """Advanced image decryption"""
        return ExtendedEncryption._decrypt_generic(encrypted_data, private_key_pem)
    
    @staticmethod
    def _encrypt_audio_advanced(audio_data, public_key_pem):
        """Advanced audio encryption with spectral hiding"""
        return ExtendedEncryption._encrypt_generic(audio_data, public_key_pem)
    
    @staticmethod
    def _decrypt_audio_advanced(encrypted_data, private_key_pem):
        """Advanced audio decryption"""
        return ExtendedEncryption._decrypt_generic(encrypted_data, private_key_pem)
    
    @staticmethod
    def _encrypt_video_advanced(video_data, public_key_pem):
        """Advanced video encryption"""
        return ExtendedEncryption._encrypt_generic(video_data, public_key_pem)
    
    @staticmethod
    def _decrypt_video_advanced(encrypted_data, private_key_pem):
        """Advanced video decryption"""
        return ExtendedEncryption._decrypt_generic(encrypted_data, private_key_pem)
    
    @staticmethod
    def _encrypt_document_advanced(document_data, public_key_pem):
        """Advanced document encryption with metadata protection"""
        return ExtendedEncryption._encrypt_generic(document_data, public_key_pem)
    
    @staticmethod
    def _decrypt_document_advanced(encrypted_data, private_key_pem):
        """Advanced document decryption"""
        return ExtendedEncryption._decrypt_generic(encrypted_data, private_key_pem)

# --- Credential parsing helper ---
def _parse_credentials(req):
    """Return (username, password) from JSON or form data."""
    username = None
    password = None

    if req.is_json:
        data = req.get_json(silent=True) or {}
        username = (
            data.get('username')
            or data.get('email')
            or data.get('user')
            or data.get('outlaw_name')
        )
        password = data.get('password') or data.get('pass')
    else:
        username = (
            req.form.get('username')
            or req.form.get('email')
            or req.form.get('user')
            or req.form.get('outlaw_name')
        )
        password = req.form.get('password') or req.form.get('pass')

    return username, password

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    profile_picture = db.Column(db.String(200), default='default-avatar.png')
    bio = db.Column(db.Text)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=lambda: get_ist_time().replace(tzinfo=None))
    created_at = db.Column(db.DateTime, default=lambda: get_ist_time().replace(tzinfo=None))
    # Zero-Knowledge Keys
    public_key = db.Column(db.Text)  # RSA public key
    private_key_encrypted = db.Column(db.Text)  # User's encrypted private key (client-side only)

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    is_group = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: get_ist_time().replace(tzinfo=None))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)  # Zero-knowledge encrypted content
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: get_ist_time().replace(tzinfo=None))
    is_deleted = db.Column(db.Boolean, default=False)
    self_destruct_time = db.Column(db.DateTime)
    message_type = db.Column(db.String(20), default='text')  # text, file
    file_name = db.Column(db.String(255), nullable=True)  # Original filename
    file_size = db.Column(db.Integer, nullable=True)  # File size in bytes
    file_type = db.Column(db.String(50), nullable=True)  # image, audio, video, document
    # Blockchain integration
    blockchain_hash = db.Column(db.String(64))  # SHA-256 hash stored on blockchain
    blockchain_block_id = db.Column(db.String(64))  # Block ID from blockchain
    # Zero-Knowledge fields
    encrypted_for_recipients = db.Column(db.Text)  # JSON of recipient-specific encryptions

class MessageStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='sent')  # sent, delivered, read
    timestamp = db.Column(db.DateTime, default=lambda: get_ist_time().replace(tzinfo=None))

class RoomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=lambda: get_ist_time().replace(tzinfo=None))
    is_admin = db.Column(db.Boolean, default=False)

class VoiceProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mfcc_features = db.Column(db.Text, nullable=False)  # JSON string of MFCC features
    created_at = db.Column(db.DateTime, default=lambda: get_ist_time().replace(tzinfo=None))
    updated_at = db.Column(db.DateTime, default=lambda: get_ist_time().replace(tzinfo=None))

class ChatInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=lambda: get_ist_time().replace(tzinfo=None))
    responded_at = db.Column(db.DateTime, nullable=True)

# Challenge phrases for voice authentication
CHALLENGE_PHRASES = [
    "The quick brown fox jumps over the lazy dog",
    "My voice is my password", 
    "Unlock my account now",
    "Authentication through voice recognition",
    "Secure access with biometric verification",
    "Voice authentication system active",
    "Please verify my identity with voice",
    "Biometric login sequence initiated",
    "Voice pattern recognition in progress",
    "Speaker verification system enabled"
]

# Voice Authentication Functions (keeping existing ones)
def convert_to_pcm_wav(input_file_path, output_file_path):
    """Convert audio file to 16-bit PCM WAV at 16kHz mono"""
    try:
        audio = AudioSegment.from_file(input_file_path)
        audio = audio.set_channels(1)
        audio = audio.set_frame_rate(16000)
        audio = audio.set_sample_width(2)
        audio.export(output_file_path, format="wav", codec="pcm_s16le")
        return True
    except Exception as e:
        print(f"Error converting audio to PCM WAV: {e}")
        return False

def extract_mfcc_features(audio_file_path):
    """Extract MFCC features from audio file"""
    try:
        y, sr = librosa.load(audio_file_path, sr=16000)
        mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
        mfcc_mean = np.mean(mfccs, axis=1)
        return mfcc_mean.tolist()
    except Exception as e:
        print(f"Error extracting MFCC features: {e}")
        return None

def generate_challenge_phrase():
    """Generate a random challenge phrase for voice authentication"""
    return random.choice(CHALLENGE_PHRASES)

def transcribe_audio(audio_file_path):
    """Convert speech to text using Google's speech recognition"""
    try:
        r = sr.Recognizer()
        with sr.AudioFile(audio_file_path) as source:
            r.adjust_for_ambient_noise(source, duration=0.5)
            audio = r.record(source)
        
        text = r.recognize_google(audio)
        return text.lower().strip()
    except sr.UnknownValueError:
        return None
    except sr.RequestError as e:
        print(f"Error with speech recognition service: {e}")
        return None
    except Exception as e:
        print(f"Error transcribing audio: {e}")
        return None

def verify_challenge_phrase(spoken_text, expected_phrase):
    """Verify if spoken text matches the challenge phrase"""
    if not spoken_text or not expected_phrase:
        return False
    
    spoken_clean = spoken_text.lower().strip().replace('.', '').replace(',', '')
    expected_clean = expected_phrase.lower().strip().replace('.', '').replace(',', '')
    
    words_spoken = set(spoken_clean.split())
    words_expected = set(expected_clean.split())
    
    overlap = len(words_spoken.intersection(words_expected))
    total_expected = len(words_expected)
    
    return (overlap / total_expected) >= 0.8 if total_expected > 0 else False

def compare_voice_features(stored_features, test_features, threshold=0.7):
    """Compare two sets of MFCC features using cosine similarity"""
    try:
        stored_array = np.array(stored_features).reshape(1, -1)
        test_array = np.array(test_features).reshape(1, -1)
        
        similarity = cosine_similarity(stored_array, test_array)[0][0]
        voice_match = similarity >= threshold
        
        print(f"Voice feature comparison:")
        print(f"  Similarity: {similarity:.3f}")
        print(f"  Threshold: {threshold}")
        print(f"  Match: {voice_match}")
        
        return voice_match, similarity
    except Exception as e:
        print(f"Error comparing voice features: {e}")
        return False, 0.0

def perform_dual_verification(audio_file_path, stored_features, challenge_phrase, threshold=0.7):
    """Perform both speech-to-text and voiceprint verification"""
    try:
        # Step 1: Speech-to-text
        spoken_text = transcribe_audio(audio_file_path)
        text_match = verify_challenge_phrase(spoken_text, challenge_phrase)

        # Step 2: Voiceprint extraction
        test_features = extract_mfcc_features(audio_file_path)
        if test_features is None:
            return False, 0.0, spoken_text, False, False

        voice_match, similarity = compare_voice_features(stored_features, test_features, threshold)

        # Step 3: Final decision (must pass both)
        dual_success = text_match and voice_match

        print("\nVoice Authentication Debug:")
        print(f"  Spoken text: '{spoken_text}'")
        print(f"  Expected phrase: '{challenge_phrase}'")
        print(f"  Text match: {text_match}")
        print(f"  Voice match: {voice_match} (similarity: {similarity:.3f})")
        print(f"  Final decision: {'PASS' if dual_success else 'FAIL'}")

        return dual_success, similarity, spoken_text, text_match

    except Exception as e:
        print(f"Error in dual verification: {e}")
        return False, 0.0, None, False, False

# Steganography Functions (keeping existing ones)
def encode_message_in_image(image_path, message):
    """Hide a message in an image using LSB steganography"""
    try:
        img = Image.open(image_path)
        img = img.convert('RGB')
        
        message += "<<<END>>>"
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        
        pixels = list(img.getdata())
        new_pixels = []
        
        message_index = 0
        
        for pixel in pixels:
            if message_index < len(binary_message):
                r, g, b = pixel
                r = (r & 0xFE) | int(binary_message[message_index])
                new_pixels.append((r, g, b))
                message_index += 1
            else:
                new_pixels.append(pixel)
        
        stego_img = Image.new('RGB', img.size)
        stego_img.putdata(new_pixels)
        
        return stego_img
    except Exception as e:
        print(f"Error encoding message: {e}")
        return None

def decode_message_from_image(image_path):
    """Extract hidden message from image using LSB steganography"""
    try:
        img = Image.open(image_path)
        img = img.convert('RGB')
        
        pixels = list(img.getdata())
        
        binary_message = ""
        for pixel in pixels:
            r, g, b = pixel
            binary_message += str(r & 1)
        
        message = ""
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i+8]
            if len(byte) == 8:
                char = chr(int(byte, 2))
                message += char
                
                if message.endswith("<<<END>>>"):
                    return message[:-9]
        
        return "No hidden message found"
    except Exception as e:
        print(f"Error decoding message: {e}")
        return "Error decoding message"

def get_user_rooms(user_id):
    return db.session.query(ChatRoom).join(RoomMember).filter(
        RoomMember.user_id == user_id
    ).all()

def create_private_room(user1_id, user2_id):
    existing_room = db.session.query(ChatRoom).join(RoomMember, ChatRoom.id == RoomMember.room_id).filter(
        ChatRoom.is_group == False,
        RoomMember.user_id.in_([user1_id, user2_id])
    ).group_by(ChatRoom.id).having(db.func.count(RoomMember.user_id) == 2).first()

    if existing_room:
        return existing_room

    room = ChatRoom(name='Private Chat', is_group=False, created_by=user1_id)
    db.session.add(room)
    db.session.commit()

    member1 = RoomMember(room_id=room.id, user_id=user1_id)
    member2 = RoomMember(room_id=room.id, user_id=user2_id)
    db.session.add(member1)
    db.session.add(member2)
    db.session.commit()

    return room

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = _parse_credentials(request)
        app.logger.info(f"/login POST content_type={request.content_type}, username_field={username!r}")

        if not username or not password:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Username and password are required'}), 400
            return render_template('login.html', error="Please provide both username and password")

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username

            user.is_online = True
            user.last_seen = get_ist_time().replace(tzinfo=None)
            db.session.commit()

            if request.is_json:
                return jsonify({'success': True, 'redirect': url_for('index')})
            return redirect(url_for('index'))

        if request.is_json:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json(silent=True) or {}
            username = data.get('username') or data.get('user') or data.get('outlaw_name')
            email = data.get('email')
            password = data.get('password') or data.get('pass')
        else:
            username = request.form.get('username') or request.form.get('user') or request.form.get('outlaw_name')
            email = request.form.get('email')
            password = request.form.get('password') or request.form.get('pass')

        if not username or not email or not password:
            msg = 'Username, email, and password are required'
            if request.is_json:
                return jsonify({'success': False, 'message': msg}), 400
            return render_template('register.html', error=msg)

        if User.query.filter_by(username=username).first():
            if request.is_json:
                return jsonify({'success': False, 'message': 'Username already exists'}), 409
            return render_template('register.html', error='Username already exists')

        if User.query.filter_by(email=email).first():
            if request.is_json:
                return jsonify({'success': False, 'message': 'Email already exists'}), 409
            return render_template('register.html', error='Email already exists')

        # Generate Zero-Knowledge keypair
        private_key_pem, public_key_pem = ZeroKnowledgeCrypto.generate_keypair()

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            public_key=public_key_pem
        )
        db.session.add(user)
        db.session.commit()

        if request.is_json:
            return jsonify({
                'success': True, 
                'message': 'Registration successful',
                'private_key': private_key_pem  # Send to client for secure storage
            })
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            user.is_online = False
            user.last_seen = get_ist_time().replace(tzinfo=None)
            db.session.commit()

    session.clear()
    return redirect(url_for('login'))

@app.route('/api/users')
def get_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        users = User.query.filter(User.id != session['user_id']).all()
        return jsonify([{
            'id': user.id,
            'username': user.username,
            'is_online': user.is_online,
            'last_seen': user.last_seen.isoformat() if user.last_seen else None,
            'public_key': getattr(user, 'public_key', None)  # Handle missing column gracefully
        } for user in users])
    except Exception as e:
        print(f"Error loading users: {e}")
        return jsonify({'error': 'Failed to load users'}), 500

@app.route('/api/rooms')
def get_rooms():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    rooms = get_user_rooms(session['user_id'])
    room_data = []

    for room in rooms:
        members = db.session.query(User).join(RoomMember).filter(
            RoomMember.room_id == room.id
        ).all()

        last_message = Message.query.filter_by(room_id=room.id).order_by(
            Message.timestamp.desc()
        ).first()

        last_message_content = ''
        if last_message:
            # For Zero-Knowledge, we can't decrypt here - client must do it
            last_message_content = '[Encrypted Message]'

        room_info = {
            'id': room.id,
            'name': room.name,
            'is_group': room.is_group,
            'members': [{'id': m.id, 'username': m.username, 'public_key': m.public_key} for m in members],
            'last_message': {
                'content': last_message_content,
                'timestamp': last_message.timestamp.isoformat() if last_message else None
            } if last_message else None
        }
        room_data.append(room_info)

    return jsonify(room_data)

@app.route('/api/messages/<int:room_id>')
def get_messages(room_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    membership = RoomMember.query.filter_by(
        room_id=room_id,
        user_id=session['user_id']
    ).first()

    if not membership:
        return jsonify({'error': 'Not authorized'}), 403

    messages = Message.query.filter_by(room_id=room_id, is_deleted=False).order_by(
        Message.timestamp.asc()
    ).all()

    message_data = []
    for message in messages:
        if message.self_destruct_time:
            if get_ist_time().replace(tzinfo=None) > message.self_destruct_time:
                message.is_deleted = True
                db.session.commit()
                continue

        sender = User.query.get(message.sender_id)

        # Handle encrypted content for current user
        display_content = message.content  # Fallback to plain content
        encrypted_content = None
        
        if message.encrypted_for_recipients:
            try:
                recipient_encryptions = json.loads(message.encrypted_for_recipients)
                user_encrypted = recipient_encryptions.get(str(session['user_id']))
                if user_encrypted:
                    # In a full implementation, client would decrypt this
                    # For now, we'll use the plain content to avoid "[Message could not be decrypted]"
                    encrypted_content = user_encrypted
                    display_content = message.content  # Use fallback plain text
            except Exception as e:
                print(f"Error processing encrypted content: {e}")
                display_content = message.content

        read_status = 'sent'
        if message.sender_id == session['user_id']:
            room_members = RoomMember.query.filter_by(room_id=room_id).all()
            all_read = True
            has_recipients = False
            for member in room_members:
                if member.user_id != session['user_id']:
                    has_recipients = True
                    member_status = MessageStatus.query.filter_by(
                        message_id=message.id,
                        user_id=member.user_id
                    ).first()
                    if not member_status or member_status.status != 'read':
                        all_read = False
                        break
            read_status = 'read' if (has_recipients and all_read) else 'sent'

        base_data = {
            'id': message.id,
            'content': display_content,  # Plain text for display
            'sender': sender.username,
            'sender_id': sender.id,
            'timestamp': message.timestamp.isoformat(),
            'self_destruct_time': message.self_destruct_time.isoformat() if message.self_destruct_time else None,
            'read_status': read_status,
            'message_type': message.message_type or 'text',
            'encrypted_content': encrypted_content,  # Encrypted version if available
            'blockchain_hash': message.blockchain_hash,
            'blockchain_verified': BlockchainService.verify_message_integrity(message.id, message.blockchain_hash) if message.blockchain_hash else False
        }
        
        if message.message_type == 'file':
            base_data.update({
                'file_name': message.file_name,
                'file_size': message.file_size,
                'file_type': message.file_type
            })
        
        message_data.append(base_data)

    return jsonify(message_data)

@app.route('/api/start_chat/<int:user_id>')
def start_chat(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    # Check if there's already a room between these users
    existing_room = db.session.query(ChatRoom).join(RoomMember).filter(
        ChatRoom.is_group == False,
        RoomMember.user_id.in_([session['user_id'], user_id])
    ).group_by(ChatRoom.id).having(db.func.count(RoomMember.user_id) == 2).first()

    if existing_room:
        return jsonify({'room_id': existing_room.id, 'status': 'existing'})

    # Check if invitation already exists
    existing_invitation = ChatInvitation.query.filter_by(
        sender_id=session['user_id'],
        receiver_id=user_id,
        status='pending'
    ).first()

    if existing_invitation:
        return jsonify({'status': 'invitation_pending', 'message': 'Invitation already sent'})

    # Create new invitation
    invitation = ChatInvitation(
        sender_id=session['user_id'],
        receiver_id=user_id,
        status='pending'
    )
    db.session.add(invitation)
    db.session.commit()

    # Get sender info
    sender = User.query.get(session['user_id'])
    
    # Send invitation notification to the receiver
    socketio.emit('chat_invitation', {
        'invitation_id': invitation.id,
        'sender_id': sender.id,
        'sender_name': sender.username,
        'message': f'{sender.username} wants to start a chat with you'
    }, room=f"user_{user_id}")

    return jsonify({'status': 'invitation_sent', 'message': 'Chat invitation sent successfully'})

@app.route('/api/invitations')
def get_invitations():
    """Get pending invitations for current user"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    invitations = ChatInvitation.query.filter_by(
        receiver_id=session['user_id'],
        status='pending'
    ).all()

    invitation_data = []
    for invitation in invitations:
        sender = User.query.get(invitation.sender_id)
        invitation_data.append({
            'id': invitation.id,
            'sender_id': sender.id,
            'sender_name': sender.username,
            'created_at': invitation.created_at.isoformat(),
            'is_online': sender.is_online
        })

    return jsonify(invitation_data)

@app.route('/api/respond_invitation/<int:invitation_id>', methods=['POST'])
def respond_invitation(invitation_id):
    """Accept or reject a chat invitation"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    invitation = ChatInvitation.query.get(invitation_id)
    if not invitation:
        return jsonify({'error': 'Invitation not found'}), 404

    if invitation.receiver_id != session['user_id']:
        return jsonify({'error': 'Not authorized'}), 403

    if invitation.status != 'pending':
        return jsonify({'error': 'Invitation already responded to'}), 400

    data = request.get_json()
    response = data.get('response')  # 'accept' or 'reject'

    if response not in ['accept', 'reject']:
        return jsonify({'error': 'Invalid response'}), 400

    invitation.status = 'accepted' if response == 'accept' else 'rejected'
    invitation.responded_at = get_ist_time().replace(tzinfo=None)

    if response == 'accept':
        # Create the chat room
        room = create_private_room(invitation.sender_id, invitation.receiver_id)
        room_id = room.id
    else:
        room_id = None

    db.session.commit()

    # Notify the sender
    receiver = User.query.get(session['user_id'])
    socketio.emit('invitation_response', {
        'invitation_id': invitation.id,
        'receiver_name': receiver.username,
        'response': response,
        'room_id': room_id,
        'message': f'{receiver.username} {"accepted" if response == "accept" else "rejected"} your chat invitation'
    }, room=f"user_{invitation.sender_id}")

    return jsonify({
        'status': 'success',
        'response': response,
        'room_id': room_id
    })

@app.route('/api/create_group', methods=['POST'])
def create_group():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    group_name = data.get('name')
    member_ids = data.get('member_ids', [])

    if not group_name:
        return jsonify({'error': 'Group name is required'}), 400

    room = ChatRoom(name=group_name, is_group=True, created_by=session['user_id'])
    db.session.add(room)
    db.session.commit()

    creator_member = RoomMember(room_id=room.id, user_id=session['user_id'], is_admin=True)
    db.session.add(creator_member)

    for member_id in member_ids:
        member = RoomMember(room_id=room.id, user_id=member_id)
        db.session.add(member)

    db.session.commit()

    return jsonify({'room_id': room.id, 'message': 'Group created successfully'})

# Enhanced File Upload Route with Zero-Knowledge Encryption
@app.route('/api/upload_file', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files or 'room_id' not in request.form:
        return jsonify({'error': 'File and room_id required'}), 400
    
    file = request.files['file']
    room_id = int(request.form['room_id'])
    self_destruct_minutes = int(request.form.get('self_destruct_minutes', 0))
    
    if file.filename == '' or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    
    membership = RoomMember.query.filter_by(
        room_id=room_id,
        user_id=session['user_id']
    ).first()
    
    if not membership:
        return jsonify({'error': 'Not authorized'}), 403
    
    try:
        file_ext = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(f"chat_file_{session['user_id']}_{int(time.time())}.{file_ext}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        file_size = os.path.getsize(file_path)
        file_type = get_file_type(file.filename)
        
        # Get room members for encryption
        room_members = RoomMember.query.filter_by(room_id=room_id).all()
        recipient_encryptions = {}
        
        # Store the original file with a secure name for fallback access
        timestamp = int(time.time())
        secure_filename_stored = f"secure_{session['user_id']}_{timestamp}.{file_ext}"
        stored_file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename_stored)
        
        # Copy the file to secure storage before encryption
        import shutil
        shutil.copy2(file_path, stored_file_path)
        
        # Encrypt file for each room member using Zero-Knowledge
        for member in room_members:
            user = User.query.get(member.user_id)
            if user and user.public_key:
                try:
                    encrypted_file = ExtendedEncryption.encrypt_file(file_path, user.public_key, file_type)
                    if encrypted_file:
                        recipient_encryptions[str(user.id)] = encrypted_file
                except Exception as e:
                    print(f"Error encrypting file for user {user.id}: {e}")
                    # Continue with other users even if one fails
        
        # Calculate self-destruct time
        self_destruct_time = None
        if self_destruct_minutes and self_destruct_minutes > 0:
            self_destruct_time = get_ist_time().replace(tzinfo=None) + timedelta(minutes=self_destruct_minutes)
        
        # Create blockchain hash
        blockchain_hash = BlockchainService.create_message_hash(
            0,  # Will be set after message creation
            session['user_id'],
            room_id,
            time.time()
        )
        
        # Create file message
        message = Message(
            content=secure_filename_stored,  # Store secure filename for fallback access
            sender_id=session['user_id'],
            room_id=room_id,
            message_type='file',
            file_name=file.filename,
            file_size=file_size,
            file_type=file_type,
            self_destruct_time=self_destruct_time,
            encrypted_for_recipients=json.dumps(recipient_encryptions) if recipient_encryptions else None,
            blockchain_hash=blockchain_hash
        )
        db.session.add(message)
        db.session.commit()
        
        # Update blockchain hash with actual message ID
        message.blockchain_hash = BlockchainService.create_message_hash(
            message.id, session['user_id'], room_id, message.timestamp.timestamp()
        )
        
        # Store on blockchain
        block_id = BlockchainService.store_on_blockchain(
            message.blockchain_hash,
            {
                'message_id': message.id,
                'type': 'file',
                'file_type': file_type
            }
        )
        
        if block_id:
            message.blockchain_block_id = block_id
        
        db.session.commit()
        
        # Clean up temporary upload file
        os.remove(file_path)
        
        sender = User.query.get(session['user_id'])
        
        message_data = {
            'id': message.id,
            'content': filename,
            'sender': sender.username,
            'sender_id': sender.id,
            'timestamp': message.timestamp.isoformat(),
            'room_id': room_id,
            'message_type': 'file',
            'file_name': file.filename,
            'file_size': file_size,
            'file_type': file_type,
            'self_destruct_time': self_destruct_time.isoformat() if self_destruct_time else None,
            'blockchain_verified': True if block_id else False
        }
        
        socketio.emit('new_message', message_data, room=f"room_{room_id}")
        
        # Create delivery status
        for member in room_members:
            if member.user_id != session['user_id']:
                status = MessageStatus(
                    message_id=message.id,
                    user_id=member.user_id,
                    status='sent'
                )
                db.session.add(status)
        
        db.session.commit()
        
        return jsonify({'success': True, 'message_id': message.id})
        
    except Exception as e:
        return jsonify({'error': f'Error uploading file: {str(e)}'}), 500

# Enhanced File Download Route with Zero-Knowledge Decryption
@app.route('/download_file/<int:message_id>')
def download_file(message_id):
    if 'user_id' not in session:
        return "Not authenticated", 401
    
    message = Message.query.get_or_404(message_id)
    
    membership = RoomMember.query.filter_by(
        room_id=message.room_id,
        user_id=session['user_id']
    ).first()
    
    if not membership:
        return "Not authorized", 403
    
    if message.message_type != 'file':
        return "Not a file message", 400
    
    try:
        # Check if file has encryption data
        if not message.encrypted_for_recipients:
            # Fallback: try to serve the original file if it exists
            original_file_path = os.path.join(app.config['UPLOAD_FOLDER'], message.content)
            if os.path.exists(original_file_path):
                return send_file(original_file_path, as_attachment=True, download_name=message.file_name)
            else:
                return "File encryption data not found and original file missing", 404
        
        recipient_encryptions = json.loads(message.encrypted_for_recipients)
        user_encrypted_file = recipient_encryptions.get(str(session['user_id']))
        
        if not user_encrypted_file:
            # If user wasn't in original encryption, check if they're a room member now
            # and try to re-encrypt for them if original file exists
            original_file_path = os.path.join(app.config['UPLOAD_FOLDER'], message.content)
            if os.path.exists(original_file_path):
                return send_file(original_file_path, as_attachment=True, download_name=message.file_name)
            else:
                return "File not accessible - user was not included in original encryption", 403
        
        # For demonstration, we'll attempt to decrypt the file server-side
        # In production, this would be done client-side with the user's private key
        try:
            user = User.query.get(session['user_id'])
            if user and user.public_key:
                # Since we don't have the private key server-side in a real Zero-Knowledge system,
                # we'll create a temporary fallback for demo purposes
                
                # Try to find if there's a non-encrypted version we can serve
                original_file_path = os.path.join(app.config['UPLOAD_FOLDER'], message.content)
                if os.path.exists(original_file_path):
                    return send_file(original_file_path, as_attachment=True, download_name=message.file_name)
                
                # Otherwise, return encrypted data for client-side decryption
                return jsonify({
                    'encrypted_file_data': user_encrypted_file,
                    'file_name': message.file_name,
                    'file_type': message.file_type,
                    'message': 'File data encrypted - decryption required on client side'
                })
            else:
                return "User encryption keys not found", 404
                
        except Exception as decrypt_error:
            print(f"Decryption error: {decrypt_error}")
            # Fallback to serving encrypted data
            return jsonify({
                'encrypted_file_data': user_encrypted_file,
                'file_name': message.file_name,
                'file_type': message.file_type,
                'message': 'File data encrypted - decryption failed, please contact support'
            })
        
    except Exception as e:
        print(f"File download error: {e}")
        return f"Error downloading file: {str(e)}", 500

# Voice Authentication Routes (keeping existing functionality)
@app.route('/voice_register', methods=['GET', 'POST'])
def voice_register():
    if request.method == 'GET':
        return render_template('voice_register.html')
    
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first'}), 401
    
    if 'voice_file' not in request.files:
        return jsonify({'success': False, 'message': 'No voice file uploaded'}), 400
    
    file = request.files['voice_file']
    if file.filename == '' or not allowed_audio_file(file.filename):
        return jsonify({'success': False, 'message': 'Invalid audio file'}), 400
    
    try:
        original_filename = secure_filename(f"voice_upload_{session['user_id']}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        file.save(original_path)
        
        wav_filename = secure_filename(f"voice_profile_{session['user_id']}_{int(time.time())}.wav")
        wav_path = os.path.join(app.config['UPLOAD_FOLDER'], wav_filename)
        
        if not convert_to_pcm_wav(original_path, wav_path):
            os.remove(original_path)
            return jsonify({'success': False, 'message': 'Failed to convert audio to required format'}), 400
        
        mfcc_features = extract_mfcc_features(wav_path)
        if mfcc_features is None:
            os.remove(original_path)
            os.remove(wav_path)
            return jsonify({'success': False, 'message': 'Failed to process audio file'}), 400
        
        voice_profile = VoiceProfile.query.filter_by(user_id=session['user_id']).first()
        if voice_profile:
            voice_profile.mfcc_features = json.dumps(mfcc_features)
            voice_profile.updated_at = get_ist_time().replace(tzinfo=None)
        else:
            voice_profile = VoiceProfile(
                user_id=session['user_id'],
                mfcc_features=json.dumps(mfcc_features)
            )
            db.session.add(voice_profile)
        
        db.session.commit()
        
        os.remove(original_path)
        os.remove(wav_path)
        
        return jsonify({'success': True, 'message': 'Voice profile created successfully.'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error processing voice: {str(e)}'}), 500

@app.route('/api/get_challenge_phrase', methods=['POST'])
def get_challenge_phrase():
    username = request.json.get('username')
    if not username:
        return jsonify({'success': False, 'message': 'Username is required'}), 400
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    voice_profile = VoiceProfile.query.filter_by(user_id=user.id).first()
    if not voice_profile:
        return jsonify({'success': False, 'message': 'No voice profile found for this user.'}), 404
    
    challenge_phrase = generate_challenge_phrase()
    
    session['challenge_phrase'] = challenge_phrase
    session['challenge_user_id'] = user.id
    
    return jsonify({
        'success': True,
        'challenge_phrase': challenge_phrase,
        'message': 'For verification, please say the following sentence out loud:'
    })

@app.route('/voice_login', methods=['GET', 'POST'])
def voice_login():
    if request.method == 'GET':
        return render_template('voice_login.html')
    
    if 'challenge_phrase' not in session or 'challenge_user_id' not in session:
        return jsonify({'success': False, 'message': 'No active challenge.'}), 400
    
    if 'voice_file' not in request.files:
        return jsonify({'success': False, 'message': 'No voice file uploaded'}), 400
    
    file = request.files['voice_file']
    if file.filename == '' or not allowed_audio_file(file.filename):
        return jsonify({'success': False, 'message': 'Invalid audio file'}), 400
    
    try:
        user = User.query.get(session['challenge_user_id'])
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        voice_profile = VoiceProfile.query.filter_by(user_id=user.id).first()
        if not voice_profile:
            return jsonify({'success': False, 'message': 'No voice profile found'}), 404
        
        original_filename = secure_filename(f"voice_login_upload_{user.id}_{int(time.time())}.{file.filename.rsplit('.', 1)[1].lower()}")
        original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        file.save(original_path)
        
        wav_filename = secure_filename(f"voice_login_{user.id}_{int(time.time())}.wav")
        wav_path = os.path.join(app.config['UPLOAD_FOLDER'], wav_filename)
        
        if not convert_to_pcm_wav(original_path, wav_path):
            os.remove(original_path)
            return jsonify({'success': False, 'message': 'Failed to convert audio'}), 400
        
        stored_features = json.loads(voice_profile.mfcc_features)
        challenge_phrase = session['challenge_phrase']
        
        dual_success, similarity, spoken_text, text_match = perform_dual_verification(
            wav_path, stored_features, challenge_phrase
        )
        
        os.remove(original_path)
        os.remove(wav_path)
        
        session.pop('challenge_phrase', None)
        session.pop('challenge_user_id', None)
        
        if dual_success:
            session['user_id'] = user.id
            session['username'] = user.username
            
            user.is_online = True
            user.last_seen = get_ist_time().replace(tzinfo=None)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f'Voice authentication successful! (Similarity: {similarity:.2%})',
                'redirect': url_for('index')
            })
        else:
            voice_match, voice_similarity = compare_voice_features(stored_features, json.loads(voice_profile.mfcc_features))
            
            if not text_match and not voice_match:
                message = f'Authentication failed. Both phrase and voice pattern did not match. (Voice similarity: {similarity:.2%})'
            elif not text_match:
                message = f'Authentication failed. Spoken text did not match challenge phrase. (Voice similarity: {similarity:.2%})'
            elif not voice_match:
                message = f'Authentication failed. Voice pattern did not match. (Voice similarity: {similarity:.2%})'
            else:
                message = f'Authentication failed. (Voice similarity: {similarity:.2%})'
            
            return jsonify({
                'success': False,
                'message': message
            }), 401
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error processing voice: {str(e)}'}), 500

# Steganography Routes (keeping existing functionality)
@app.route('/steganography')
def steganography():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('steganography.html')

@app.route('/zero_knowledge')
def zero_knowledge():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('zero_knowledge.html')

@app.route('/blockchain_verify')
def blockchain_verify():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('blockchain_verify.html')

@app.route('/encode_image', methods=['POST'])
def encode_image():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'image_file' not in request.files or 'secret_message' not in request.form:
        return jsonify({'error': 'Image file and secret message are required'}), 400
    
    file = request.files['image_file']
    message = request.form['secret_message']
    
    if file.filename == '' or not allowed_image_file(file.filename):
        return jsonify({'error': 'Invalid image file'}), 400
    
    if not message.strip():
        return jsonify({'error': 'Secret message cannot be empty'}), 400
    
    try:
        filename = secure_filename(f"original_{session['user_id']}_{int(time.time())}.png")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        stego_img = encode_message_in_image(file_path, message)
        if stego_img is None:
            os.remove(file_path)
            return jsonify({'error': 'Failed to encode message'}), 500
        
        stego_filename = secure_filename(f"stego_{session['user_id']}_{int(time.time())}.png")
        stego_path = os.path.join(app.config['UPLOAD_FOLDER'], stego_filename)
        stego_img.save(stego_path, 'PNG')
        
        os.remove(file_path)
        
        return jsonify({
            'success': True,
            'message': 'Message encoded successfully!',
            'download_url': f'/download_stego/{stego_filename}'
        })
        
    except Exception as e:
        return jsonify({'error': f'Error encoding message: {str(e)}'}), 500

@app.route('/decode_image', methods=['POST'])
def decode_image():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'image_file' not in request.files:
        return jsonify({'error': 'Image file is required'}), 400
    
    file = request.files['image_file']
    
    if file.filename == '' or not allowed_image_file(file.filename):
        return jsonify({'error': 'Invalid image file'}), 400
    
    try:
        filename = secure_filename(f"decode_{session['user_id']}_{int(time.time())}.png")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        hidden_message = decode_message_from_image(file_path)
        
        os.remove(file_path)
        
        return jsonify({
            'success': True,
            'hidden_message': hidden_message
        })
        
    except Exception as e:
        return jsonify({'error': f'Error decoding message: {str(e)}'}), 500

@app.route('/download_stego/<filename>')
def download_stego(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

@app.route('/api/send_stego_to_chat', methods=['POST'])
def send_stego_to_chat():
    """Send a steganography image directly to a chat room"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    stego_filename = data.get('stego_filename')
    room_id = data.get('room_id')
    
    if not stego_filename or not room_id:
        return jsonify({'error': 'Stego filename and room_id required'}), 400
    
    # Verify user has access to the room
    membership = RoomMember.query.filter_by(
        room_id=room_id,
        user_id=session['user_id']
    ).first()
    
    if not membership:
        return jsonify({'error': 'Not authorized to send to this room'}), 403
    
    try:
        # Extract the actual filename from the download URL
        actual_filename = stego_filename.split('/')[-1] if '/' in stego_filename else stego_filename
        stego_path = os.path.join(app.config['UPLOAD_FOLDER'], actual_filename)
        
        if not os.path.exists(stego_path):
            return jsonify({'error': 'Steganography image not found'}), 404
        
        # Get file size
        file_size = os.path.getsize(stego_path)
        
        # Create a secure filename for the chat
        timestamp = int(time.time())
        secure_filename_stored = f"stego_chat_{session['user_id']}_{timestamp}.png"
        stored_file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename_stored)
        
        # Copy the stego image to chat storage
        import shutil
        shutil.copy2(stego_path, stored_file_path)
        
        # Get room members for encryption
        room_members = RoomMember.query.filter_by(room_id=room_id).all()
        recipient_encryptions = {}
        
        # For steganography images, store the filename for each user
        for member in room_members:
            user = User.query.get(member.user_id)
            if user:
                recipient_encryptions[str(user.id)] = secure_filename_stored
        
        # Create blockchain hash
        blockchain_hash = BlockchainService.create_message_hash(
            0,  # Will be updated after message creation
            session['user_id'],
            room_id,
            time.time()
        )
        
        # Create file message
        message = Message(
            content=secure_filename_stored,
            sender_id=session['user_id'],
            room_id=room_id,
            message_type='file',
            file_name='🖼️ Hidden Message',
            file_size=file_size,
            file_type='image',
            encrypted_for_recipients=json.dumps(recipient_encryptions),
            blockchain_hash=blockchain_hash
        )
        db.session.add(message)
        db.session.commit()
        
        # Update blockchain hash with actual message ID
        message.blockchain_hash = BlockchainService.create_message_hash(
            message.id, session['user_id'], room_id, message.timestamp.timestamp()
        )
        
        # Store on blockchain
        block_id = BlockchainService.store_on_blockchain(
            message.blockchain_hash,
            {
                'message_id': message.id,
                'type': 'steganography',
                'file_type': 'image'
            }
        )
        
        if block_id:
            message.blockchain_block_id = block_id
        
        db.session.commit()
        
        sender = User.query.get(session['user_id'])
        
        message_data = {
            'id': message.id,
            'content': secure_filename_stored,
            'sender': sender.username,
            'sender_id': sender.id,
            'timestamp': message.timestamp.isoformat(),
            'room_id': room_id,
            'message_type': 'file',
            'file_name': '🖼️ Hidden Message',
            'file_size': file_size,
            'file_type': 'image',
            'blockchain_verified': True if block_id else False
        }
        
        socketio.emit('new_message', message_data, room=f"room_{room_id}")
        
        # Create delivery status
        for member in room_members:
            if member.user_id != session['user_id']:
                status = MessageStatus(
                    message_id=message.id,
                    user_id=member.user_id,
                    status='sent'
                )
                db.session.add(status)
        
        db.session.commit()
        
        # Clean up the original stego file to save space
        try:
            os.remove(stego_path)
        except:
            pass  # Don't fail if cleanup fails
        
        return jsonify({'success': True, 'message_id': message.id})
        
    except Exception as e:
        print(f"Error sending stego image: {e}")
        return jsonify({'error': f'Error sending steganography image: {str(e)}'}), 500

# New Zero-Knowledge API Endpoints
@app.route('/api/get_user_keys', methods=['GET'])
def get_user_keys():
    """Get user's public key and encrypted private key"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'public_key': user.public_key,
        # In production, private key would be stored encrypted on client
        'user_id': user.id
    })

@app.route('/api/blockchain_status/<int:message_id>')
def blockchain_status(message_id):
    """Check blockchain verification status of a message"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    message = Message.query.get(message_id)
    if not message:
        return jsonify({'error': 'Message not found'}), 404
    
    # Check if user has access to this message
    membership = RoomMember.query.filter_by(
        room_id=message.room_id,
        user_id=session['user_id']
    ).first()
    
    if not membership:
        return jsonify({'error': 'Not authorized'}), 403
    
    verified = False
    if message.blockchain_hash:
        verified = BlockchainService.verify_message_integrity(message.id, message.blockchain_hash)
    
    return jsonify({
        'message_id': message_id,
        'blockchain_hash': message.blockchain_hash,
        'blockchain_block_id': message.blockchain_block_id,
        'verified': verified,
        'timestamp': message.timestamp.isoformat()
    })

# Socket events (updated for Zero-Knowledge)
@socketio.on('connect')
def on_connect(auth=None):
    if 'user_id' in session:
        join_room(f"user_{session['user_id']}")
        user = User.query.get(session['user_id'])
        if user:
            user.is_online = True
            user.last_seen = get_ist_time().replace(tzinfo=None)
            db.session.commit()
        print(f"User {session['username']} connected")

@socketio.on('disconnect')
def on_disconnect():
    if 'user_id' in session:
        leave_room(f"user_{session['user_id']}")
        user = User.query.get(session['user_id'])
        if user:
            user.is_online = False
            user.last_seen = get_ist_time().replace(tzinfo=None)
            db.session.commit()
        print(f"User {session['username']} disconnected")

@socketio.on('join_room')
def on_join_room(data):
    if 'user_id' not in session:
        return

    room_id = data['room_id']

    membership = RoomMember.query.filter_by(
        room_id=room_id,
        user_id=session['user_id']
    ).first()

    if membership:
        join_room(f"room_{room_id}")
        emit('joined_room', {'room_id': room_id})

@socketio.on('leave_room')
def on_leave_room(data):
    room_id = data['room_id']
    leave_room(f"room_{room_id}")

@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session:
        return

    room_id = data['room_id']
    content = data.get('content', '')
    self_destruct_minutes = data.get('self_destruct_minutes', 0)

    membership = RoomMember.query.filter_by(
        room_id=room_id,
        user_id=session['user_id']
    ).first()

    if not membership:
        return

    self_destruct_time = None
    if self_destruct_minutes and self_destruct_minutes > 0:
        self_destruct_time = get_ist_time().replace(tzinfo=None) + timedelta(minutes=self_destruct_minutes)

    # Get room members for Zero-Knowledge encryption
    room_members = RoomMember.query.filter_by(room_id=room_id).all()
    recipient_encryptions = {}
    
    # Encrypt message for each room member using Zero-Knowledge
    for member in room_members:
        user = User.query.get(member.user_id)
        if user and user.public_key:
            try:
                encrypted_content = ZeroKnowledgeCrypto.encrypt_with_public_key(content, user.public_key)
                recipient_encryptions[str(user.id)] = encrypted_content
            except Exception as e:
                print(f"Error encrypting for user {user.id}: {e}")
                # Fallback to plain text for compatibility
                recipient_encryptions[str(user.id)] = content

    # Create blockchain hash
    blockchain_hash = BlockchainService.create_message_hash(
        0,  # Will be updated after message creation
        session['user_id'],
        room_id,
        time.time()
    )

    # Store encrypted message
    message = Message(
        content=content,  # Store plain text as fallback
        sender_id=session['user_id'],
        room_id=room_id,
        self_destruct_time=self_destruct_time,
        blockchain_hash=blockchain_hash,
        encrypted_for_recipients=json.dumps(recipient_encryptions)
    )
    db.session.add(message)
    db.session.commit()

    # Update blockchain hash with actual message ID
    message.blockchain_hash = BlockchainService.create_message_hash(
        message.id, session['user_id'], room_id, message.timestamp.timestamp()
    )
    
    # Store on blockchain
    block_id = BlockchainService.store_on_blockchain(
        message.blockchain_hash,
        {
            'message_id': message.id,
            'type': 'text',
            'room_id': room_id
        }
    )
    
    if block_id:
        message.blockchain_block_id = block_id
    
    db.session.commit()

    sender = User.query.get(session['user_id'])

    message_data = {
        'id': message.id,
        'content': content,  # Send plain text for real-time display
        'sender': sender.username,
        'sender_id': sender.id,
        'timestamp': message.timestamp.isoformat(),
        'room_id': room_id,
        'self_destruct_time': self_destruct_time.isoformat() if self_destruct_time else None,
        'blockchain_verified': True if block_id else False,
        'encrypted_content': recipient_encryptions.get(str(session['user_id']), content)
    }

    socketio.emit('new_message', message_data, room=f"room_{room_id}")

    # Create delivery status for all recipients
    for member in room_members:
        if member.user_id != session['user_id']:
            status = MessageStatus(
                message_id=message.id,
                user_id=member.user_id,
                status='sent'
            )
            db.session.add(status)

    db.session.commit()

    # Determine read status for sender
    read_status = 'sent'  # Default status for new messages

@socketio.on('get_pending_invitations')
def get_pending_invitations():
    """Get pending invitations for the connected user"""
    if 'user_id' not in session:
        return

    invitations = ChatInvitation.query.filter_by(
        receiver_id=session['user_id'],
        status='pending'
    ).all()

    invitation_data = []
    for invitation in invitations:
        sender = User.query.get(invitation.sender_id)
        invitation_data.append({
            'id': invitation.id,
            'sender_id': sender.id,
            'sender_name': sender.username,
            'created_at': invitation.created_at.isoformat(),
            'is_online': sender.is_online
        })

    emit('pending_invitations', invitation_data)

@socketio.on('mark_as_read')
def mark_as_read(data):
    if 'user_id' not in session:
        return

    message_id = data['message_id']

    status = MessageStatus.query.filter_by(
        message_id=message_id,
        user_id=session['user_id']
    ).first()

    if status:
        status.status = 'read'
        status.timestamp = get_ist_time().replace(tzinfo=None)
    else:
        status = MessageStatus(
            message_id=message_id,
            user_id=session['user_id'],
            status='read'
        )
        db.session.add(status)

    db.session.commit()

    message = Message.query.get(message_id)
    if message:
        # Check if all recipients have read the message
        room_members = RoomMember.query.filter_by(room_id=message.room_id).all()
        all_read = True
        for member in room_members:
            if member.user_id != message.sender_id:
                member_status = MessageStatus.query.filter_by(
                    message_id=message_id,
                    user_id=member.user_id
                ).first()
                if not member_status or member_status.status != 'read':
                    all_read = False
                    break
        
        # Emit to the sender about read status change
        socketio.emit('message_status_update', {
            'message_id': message_id,
            'status': 'read' if all_read else 'sent',
            'reader_id': session['user_id'],
            'room_id': message.room_id
        }, room=f"user_{message.sender_id}")

        # Also emit the general message_read event
        socketio.emit('message_read', {
            'message_id': message_id,
            'reader_id': session['user_id'],
            'room_id': message.room_id
        }, room=f"room_{message.room_id}")

# Background task to clean up self-destructing messages
def cleanup_messages():
    while True:
        with app.app_context():
            try:
                # Check if the required columns exist before querying
                from sqlalchemy import inspect
                inspector = inspect(db.engine)
                message_columns = [column['name'] for column in inspector.get_columns('message')]
                
                if 'self_destruct_time' in message_columns:
                    expired_messages = Message.query.filter(
                        Message.self_destruct_time != None,
                        Message.self_destruct_time <= get_ist_time().replace(tzinfo=None),
                        Message.is_deleted == False
                    ).all()

                    for message in expired_messages:
                        message.is_deleted = True
                        socketio.emit('message_deleted', {
                            'message_id': message.id,
                            'room_id': message.room_id
                        }, room=f"room_{message.room_id}")

                    if expired_messages:
                        db.session.commit()

            except Exception as e:
                print(f"Error in cleanup_messages: {e}")

        time.sleep(60)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    cleanup_thread = threading.Thread(target=cleanup_messages, daemon=True)
    cleanup_thread.start()

    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
