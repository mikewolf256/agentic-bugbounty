FROM python:3.11-slim

WORKDIR /app
COPY app /app

RUN pip install --no-cache-dir flask pyjwt

EXPOSE 5000
CMD ["python", "app.py"]

