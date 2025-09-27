#!/bin/bash

# Outlaw Telegraph Deployment Script
# Usage: ./deploy.sh [platform]
# Platforms: heroku, digitalocean, docker

set -e  # Exit on any error

PLATFORM=${1:-"heroku"}
APP_NAME="outlaw-telegraph"

echo "🤠 Deploying Outlaw Telegraph to $PLATFORM..."

case $PLATFORM in
    "heroku")
        echo "📦 Deploying to Heroku..."
        
        # Check if Heroku CLI is installed
        if ! command -v heroku &> /dev/null; then
            echo "❌ Heroku CLI not found. Please install it first."
            echo "Visit: https://devcenter.heroku.com/articles/heroku-cli"
            exit 1
        fi
        
        # Login to Heroku
        echo "🔐 Logging into Heroku..."
        heroku auth:whoami || heroku login
        
        # Create app if it doesn't exist
        if ! heroku apps:info $APP_NAME &> /dev/null; then
            echo "🆕 Creating new Heroku app: $APP_NAME"
            heroku create $APP_NAME
        fi
        
        # Set environment variables
        echo "⚙️ Setting environment variables..."
        heroku config:set FLASK_ENV=production -a $APP_NAME
        heroku config:set FLASK_SECRET_KEY="$(openssl rand -hex 32)" -a $APP_NAME
        
        # Add PostgreSQL addon
        if ! heroku addons:info heroku-postgresql -a $APP_NAME &> /dev/null; then
            echo "🗄️ Adding PostgreSQL database..."
            heroku addons:create heroku-postgresql:hobby-dev -a $APP_NAME
        fi
        
        # Deploy
        echo "🚀 Deploying application..."
        git add .
        git commit -m "Deploy to Heroku" || true
        git push heroku main
        
        # Open app
        echo "✅ Deployment complete!"
        heroku open -a $APP_NAME
        ;;
        
    "docker")
        echo "🐳 Building Docker container..."
        
        # Create Dockerfile if it doesn't exist
        if [ ! -f Dockerfile ]; then
            cat > Dockerfile << 'EOF'
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libsndfile1 \
    ffmpeg \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create uploads directory
RUN mkdir -p uploads

# Set environment variables
ENV FLASK_ENV=production
ENV PORT=5000

# Expose port
EXPOSE 5000

# Run application
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "main:app"]
EOF
        fi
        
        # Build image
        docker build -t outlaw-telegraph .
        
        # Run container
        echo "🏃 Running Docker container..."
        docker run -d \
            --name outlaw-telegraph \
            -p 5000:5000 \
            -e FLASK_SECRET_KEY="$(openssl rand -hex 32)" \
            -e DATABASE_URL="sqlite:///messenger.db" \
            -v $(pwd)/uploads:/app/uploads \
            outlaw-telegraph
        
        echo "✅ Docker container running on http://localhost:5000"
        ;;
        
    "digitalocean")
        echo "🌊 DigitalOcean deployment requires manual server setup."
        echo "Please follow the detailed instructions in DEPLOYMENT.md"
        echo "Quick steps:"
        echo "1. Create a DigitalOcean droplet (Ubuntu 20.04)"
        echo "2. SSH into your server"
        echo "3. Run: git clone <your-repo-url>"
        echo "4. Follow the server setup instructions in DEPLOYMENT.md"
        ;;
        
    *)
        echo "❌ Unknown platform: $PLATFORM"
        echo "Supported platforms: heroku, docker, digitalocean"
        exit 1
        ;;
esac

echo ""
echo "🎉 Deployment script completed!"
echo "📚 For detailed instructions, see DEPLOYMENT.md"
echo "🐛 For issues, check the logs and troubleshooting guide"