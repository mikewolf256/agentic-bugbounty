FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir grpcio grpcio-tools flask

# Copy proto file first
COPY app/proto/ /app/app/proto/

# Generate gRPC code from proto file
RUN python -m grpc_tools.protoc -I app/proto --python_out=app --grpc_python_out=app app/proto/user.proto

# Copy rest of app files
COPY app/ /app/

EXPOSE 5000
EXPOSE 50051

CMD ["python", "app.py"]

