# 🚀 Outlaw Telegraph - Deployment Guide

## Table of Contents
- [Quick Deployment Options](#quick-deployment-options)
- [Production Deployment](#production-deployment)
- [Security Hardening](#security-hardening)
- [Monitoring & Maintenance](#monitoring--maintenance)

---

## Quick Deployment Options

### 1. 🔥 Replit (Fastest - 2 minutes)
**Perfect for demos and testing**

1. **Fork on Replit:**
   - Go to [Replit](https://replit.com)
   - Import from GitHub or upload your code
   - Replit automatically detects Python and installs dependencies

2. **Configuration:**
   ```bash
   # .replit file (auto-generated)
   run = "python main.py"
   language = "python3"
   ```

3. **Environment Variables:**
   ```bash
   FLASK_SECRET_KEY=your-secret-key-here
   ```

4. **Run:** Click the "Run" button
5. **Access:** Use the provided Replit URL

**Pros:** Instant deployment, free tier available, great for demos
**Cons:** Limited resources, not suitable for production scale

---

### 2. 🌊 Heroku (Easy - 15 minutes)
**Good for small to medium production deployments**

#### Setup Steps:

1. **Install Heroku CLI:**
   ```bash
   # macOS
   brew install heroku/brew/heroku
   
   # Windows
   # Download from https://devcenter.heroku.com/articles/heroku-cli
   
   # Linux
   curl https://cli-assets.heroku.com/install.sh | sh
   ```

2. **Prepare Your App:**
   ```bash
   # Create Procfile
   echo "web: gunicorn main:app" > Procfile
   
   # Create runtime.txt
   echo "python-3.11.0" > runtime.txt
   ```

3. **Deploy:**
   ```bash
   # Login to Heroku
   heroku login
   
   # Create app
   heroku create your-outlaw-telegraph
   
   # Set environment variables
   heroku config:set FLASK_SECRET_KEY="your-super-secret-key"
   heroku config:set FLASK_ENV="production"
   
   # Deploy
   git add .
   git commit -m "Deploy to Heroku"
   git push heroku main
   ```

4. **Configure Add-ons:**
   ```bash
   # PostgreSQL database (recommended for production)
   heroku addons:create heroku-postgresql:hobby-dev
   
   # Redis for session management (optional)
   heroku addons:create heroku-redis:hobby-dev
   ```

**Pros:** Easy deployment, automatic scaling, good for production
**Cons:** Costs money for decent resources, some limitations

---

### 3. 🐙 GitHub Pages + Netlify (Static + Serverless)
**For frontend-only version with serverless backend**

This requires significant refactoring to separate frontend/backend, so I'll skip the detailed steps unless you're interested.

---

## Production Deployment Options

### 1. 🌊 DigitalOcean Droplet (Recommended)
**Full control, great performance, reasonable cost**

#### Server Setup (Ubuntu 20.04):

```bash
# 1. Create droplet and connect via SSH
ssh root@your-server-ip

# 2. Update system
apt update && apt upgrade -y

# 3. Install Python and dependencies
apt install python3 python3-pip python3-venv nginx supervisor postgresql postgresql-contrib -y

# 4. Create application user
adduser outlaw
usermod -aG sudo outlaw
su - outlaw

# 5. Clone your repository
git clone https://github.com/your-username/outlaw-telegraph.git
cd outlaw-telegraph

# 6. Create virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 7. Configure PostgreSQL
sudo -u postgres createuser --interactive outlaw
sudo -u postgres createdb outlaw_telegraph
```

#### Application Configuration:

```python
# config.py
import os
from urllib.parse import urlparse

class ProductionConfig:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'fallback-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://outlaw:password@localhost/outlaw_telegraph'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File upload settings
    UPLOAD_FOLDER = '/home/outlaw/outlaw-telegraph/uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    
    # Security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
```

#### Nginx Configuration:

```nginx
# /etc/nginx/sites-available/outlaw-telegraph
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /socket.io {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Supervisor Configuration:

```ini
# /etc/supervisor/conf.d/outlaw-telegraph.conf
[program:outlaw-telegraph]
command=/home/outlaw/outlaw-telegraph/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 main:app
directory=/home/outlaw/outlaw-telegraph
user=outlaw
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/outlaw-telegraph.log
```

#### SSL with Let's Encrypt:

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx -y

# Get SSL certificate
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Auto-renewal (already set up by certbot)
sudo crontab -l | grep certbot
```

---

### 2. ☁️ AWS EC2 (Enterprise)
**Scalable, professional, but complex**

#### Launch EC2 Instance:
1. Choose Ubuntu 20.04 LTS AMI
2. Select instance type (t3.micro for testing, t3.medium+ for production)
3. Configure security groups (HTTP/HTTPS/SSH)
4. Launch with key pair

#### Setup (similar to DigitalOcean):
```bash
# Connect to instance
ssh -i your-key.pem ubuntu@your-ec2-public-ip

# Follow similar setup steps as DigitalOcean
# Additional: Configure Load Balancer, RDS, S3 for files
```

#### Additional AWS Services:
- **RDS**: Managed PostgreSQL database
- **S3**: File storage for uploads
- **CloudFront**: CDN for global performance
- **Route 53**: DNS management
- **ELB**: Load balancing for multiple instances

---

### 3. 🐳 Docker Deployment
**Containerized, portable, modern**

#### Dockerfile:
```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libsndfile1 \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create uploads directory
RUN mkdir -p uploads

# Expose port
EXPOSE 5000

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "main:app"]
```

#### Docker Compose:
```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_SECRET_KEY=your-secret-key
      - DATABASE_URL=postgresql://postgres:password@db:5432/outlaw_telegraph
    volumes:
      - ./uploads:/app/uploads
    depends_on:
      - db
      - redis

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=outlaw_telegraph
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - app

volumes:
  postgres_data:
```

#### Deploy:
```bash
# Build and run
docker-compose up -d

# View logs
docker-compose logs -f

# Scale workers
docker-compose up -d --scale app=3
```

---

## Security Hardening

### 1. Environment Variables
```bash
# .env file (never commit to git)
FLASK_SECRET_KEY=your-256-bit-secret-key-here
DATABASE_URL=postgresql://user:password@localhost/dbname
UPLOAD_FOLDER=/secure/path/uploads
MAX_CONTENT_LENGTH=104857600

# Voice authentication settings
VOICE_SIMILARITY_THRESHOLD=0.7
CHALLENGE_PHRASE_COUNT=10

# Security settings
SESSION_TIMEOUT=1800
MAX_LOGIN_ATTEMPTS=5
RATE_LIMIT_PER_MINUTE=60
```

### 2. Production Security Updates
```python
# Add to main.py for production
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Security headers
Talisman(app, force_https=True)

# CSRF protection
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Content Security Policy
CSP = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline'",
    'media-src': "'self'",
    'connect-src': "'self' wss:",
}
```

### 3. Database Security
```python
# Use environment-based configuration
import os
from urllib.parse import quote_plus

# Secure database connection
password = quote_plus(os.environ.get('DB_PASSWORD'))
DATABASE_URL = f"postgresql://user:{password}@host:port/database?sslmode=require"

# Connection pooling
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 20,
    'pool_recycle': 3600,
    'pool_pre_ping': True
}
```

### 4. File Security
```python
# Secure file handling
import magic

def secure_file_upload(file):
    # Validate file type with magic numbers
    file_type = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    
    # Whitelist allowed types
    allowed_types = {
        'image/png', 'image/jpeg', 'image/gif',
        'audio/wav', 'audio/mpeg', 'audio/ogg',
        'application/pdf', 'text/plain'
    }
    
    if file_type not in allowed_types:
        raise ValueError("File type not allowed")
    
    # Scan for malware (integrate with ClamAV in production)
    # scan_file_for_malware(file)
    
    return file
```

---

## Monitoring & Maintenance

### 1. Logging Configuration
```python
# logging_config.py
import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging(app):
    if not app.debug:
        # File logging
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = RotatingFileHandler(
            'logs/outlaw_telegraph.log', 
            maxBytes=10240000, 
            backupCount=10
        )
        
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Outlaw Telegraph startup')
```

### 2. Health Check Endpoint
```python
# Add to main.py
@app.route('/health')
def health_check():
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        
        # Check file system
        os.path.exists(app.config['UPLOAD_FOLDER'])
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0.0'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500
```

### 3. Monitoring with Prometheus
```python
# monitoring.py
from prometheus_flask_exporter import PrometheusMetrics

def setup_monitoring(app):
    metrics = PrometheusMetrics(app)
    
    # Custom metrics
    voice_auth_attempts = metrics.counter(
        'voice_auth_attempts_total',
        'Total voice authentication attempts',
        labels={'status': lambda: 'success'}
    )
    
    message_encryption_time = metrics.histogram(
        'message_encryption_seconds',
        'Time spent encrypting messages'
    )
    
    return metrics
```

### 4. Backup Strategy
```bash
#!/bin/bash
# backup.sh

# Database backup
pg_dump $DATABASE_URL > backups/db_$(date +%Y%m%d_%H%M%S).sql

# File backup
tar -czf backups/files_$(date +%Y%m%d_%H%M%S).tar.gz uploads/

# Cleanup old backups (keep 30 days)
find backups/ -name "*.sql" -mtime +30 -delete
find backups/ -name "*.tar.gz" -mtime +30 -delete

# Upload to cloud storage
aws s3 sync backups/ s3://your-backup-bucket/outlaw-telegraph/
```

---

## Performance Optimization

### 1. Database Optimization
```python
# Add indexes for common queries
class Message(db.Model):
    # ... existing fields ...
    
    __table_args__ = (
        db.Index('idx_message_room_timestamp', 'room_id', 'timestamp'),
        db.Index('idx_message_sender', 'sender_id'),
        db.Index('idx_message_deleted', 'is_deleted'),
    )
```

### 2. Caching Layer
```python
# Add Redis caching
from flask_caching import Cache

cache = Cache(app, config={
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
})

@cache.memoize(timeout=300)
def get_user_public_key(user_id):
    user = User.query.get(user_id)
    return user.public_key if user else None
```

### 3. CDN for Static Files
```nginx
# Nginx configuration for static files
location /static {
    alias /home/outlaw/outlaw-telegraph/static;
    expires 1y;
    add_header Cache-Control "public, immutable";
}

location /uploads {
    alias /home/outlaw/outlaw-telegraph/uploads;
    expires 1d;
    add_header Cache-Control "private";
}
```

---

## Cost Estimation

### Hosting Costs (Monthly):

| Platform | Specs | Cost | Best For |
|----------|-------|------|----------|
| **Replit** | Limited resources | $0-20 | Demo/Testing |
| **Heroku** | 1 dyno + Postgres | $25-50 | Small production |
| **DigitalOcean** | 2GB RAM droplet | $12-25 | Medium production |
| **AWS EC2** | t3.medium + RDS | $50-100 | Enterprise |
| **Docker + VPS** | 4GB RAM server | $20-40 | Self-managed |

### Additional Costs:
- **Domain**: $10-15/year
- **SSL Certificate**: Free (Let's Encrypt)
- **Backup Storage**: $5-10/month
- **Monitoring**: $0-30/month
- **CDN**: $0-20/month

---

## Quick Start Commands

### For Immediate Public Access:

```bash
# Option 1: Replit (2 minutes)
# Just upload your code to Replit and click Run

# Option 2: Heroku (15 minutes)
heroku create your-app-name
git push heroku main
heroku open

# Option 3: DigitalOcean (30 minutes)
# Create droplet, SSH in, follow setup steps above

# Option 4: Local with ngrok (instant public tunnel)
pip install pyngrok
python main.py &
ngrok http 5000
# Use the ngrok URL for public access
```

---

**Choose the deployment option that best fits your needs, budget, and technical requirements. For a quick demo, Replit is perfect. For serious production use, DigitalOcean or AWS provide the best balance of control and cost.**