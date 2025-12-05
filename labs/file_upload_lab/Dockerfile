FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask

COPY app/ /app/

# Create uploads directory
RUN mkdir -p /app/uploads

EXPOSE 5000

CMD ["python", "app.py"]

