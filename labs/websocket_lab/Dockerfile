FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask flask-socketio websockets

COPY app/ /app/

EXPOSE 5000
EXPOSE 5001

CMD ["python", "app.py"]

