FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy callback server
COPY tools/callback_server.py .
COPY tools/callback_correlator.py .
COPY tools/ngrok_helper.py .

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8080/')" || exit 1

# Run callback server
CMD ["python", "callback_server.py"]

