FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask flask-caching

COPY app/ /app/

EXPOSE 5000

CMD ["python", "app.py"]

