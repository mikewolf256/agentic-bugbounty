# New Vulnerability Labs Summary

## Overview
Created 7 new Docker lab containers for testing the new vulnerability validation tools.

## Labs Created

### 1. XXE Lab (`labs/xxe_lab/`)
- **Port**: 5005
- **Vulnerabilities**:
  - External entity injection with OOB callbacks
  - Local file inclusion (`/etc/passwd`)
  - SSRF via XXE
- **Endpoints**: `/parse`, `/upload`, `/api/xml`
- **Files**: Dockerfile, app/app.py, lab_metadata.json, requirements.txt

### 2. Business Logic Lab (`labs/business_logic_lab/`)
- **Port**: 5006
- **Vulnerabilities**:
  - Pricing manipulation (negative prices, user-provided prices)
  - Workflow bypasses (skipping payment steps)
  - Rate limit bypasses (X-Forwarded-For header)
  - State transition vulnerabilities
- **Endpoints**: `/cart`, `/checkout`, `/api/purchase`, `/api/rate-limit`, `/api/state-transition`
- **Files**: Dockerfile, app/app.py, lab_metadata.json, requirements.txt

### 3. Cloud Lab (`labs/cloud_lab/`)
- **Port**: 5007
- **Vulnerabilities**:
  - AWS metadata endpoint exposure (`/latest/meta-data/`)
  - GCP metadata endpoint exposure (`/computeMetadata/v1/`)
  - Azure metadata endpoint exposure (`/metadata/instance`)
  - IAM credential exposure
  - S3 bucket misconfigurations
- **Endpoints**: `/latest/meta-data/`, `/computeMetadata/v1/`, `/metadata/instance`, `/s3/bucket`, `/fetch`
- **Files**: Dockerfile, app/app.py, lab_metadata.json, requirements.txt

### 4. Template Injection Lab (`labs/template_injection_lab/`)
- **Port**: 5008
- **Vulnerabilities**:
  - Jinja2 template injection
  - Unsafe template rendering
- **Endpoints**: `/render`, `/search`, `/api/render`
- **Files**: Dockerfile, app/app.py, lab_metadata.json, requirements.txt

### 5. Deserialization Lab (`labs/deserialization_lab/`)
- **Port**: 5009
- **Vulnerabilities**:
  - Python pickle deserialization RCE
  - YAML deserialization with unsafe loader
- **Endpoints**: `/pickle`, `/yaml`, `/api/deserialize`
- **Files**: Dockerfile, app/app.py, lab_metadata.json, requirements.txt

### 6. GraphQL Lab (`labs/graphql_lab/`)
- **Port**: 5010
- **Vulnerabilities**:
  - GraphQL introspection enabled
  - Depth-based DoS (no depth limits)
  - Query complexity issues (no complexity limits)
  - Recursive queries allowed
- **Endpoints**: `/graphql` (GraphQL Playground)
- **Files**: Dockerfile, app/app.py, lab_metadata.json, requirements.txt

### 7. gRPC Lab (`labs/grpc_lab/`)
- **Ports**: 5011 (HTTP), 5012 (gRPC)
- **Vulnerabilities**:
  - Unauthenticated gRPC endpoints
  - Service enumeration
  - Sensitive data exposure (API keys, secrets)
- **Endpoints**: `/` (HTTP), `grpc_lab:50051` (gRPC)
- **Files**: Dockerfile, app/app.py, app/proto/user.proto, lab_metadata.json, requirements.txt

## Docker Compose Integration

All labs have been added to `docker-compose.yml`:
- Ports: 5005-5011 (HTTP), 5012 (gRPC)
- Network: `lab_network`
- Build context: `./labs/{lab_name}`

## Testing

To test the labs:

```bash
# Build and start all labs
docker-compose up --build

# Test individual lab
curl http://localhost:5005/  # XXE lab
curl http://localhost:5006/  # Business Logic lab
curl http://localhost:5007/  # Cloud lab
curl http://localhost:5008/  # Template Injection lab
curl http://localhost:5009/  # Deserialization lab
curl http://localhost:5010/graphql  # GraphQL lab
curl http://localhost:5011/  # gRPC lab (HTTP interface)
```

## Validation Tools

Each lab is designed to be detected by our validation tools:
- `tools/xxe_validator.py` → `xxe_lab`
- `tools/business_logic_analyzer.py` → `business_logic_lab`
- `tools/cloud_metadata_tester.py` → `cloud_lab`
- `tools/template_injection_tester.py` → `template_injection_lab`
- `tools/deserialization_tester.py` → `deserialization_lab`
- `tools/graphql_deep_analyzer.py` → `graphql_lab`
- `tools/grpc_analyzer.py` → `grpc_lab`

## Next Steps

1. Build and test all labs: `docker-compose up --build`
2. Run validation tools against each lab
3. Verify findings match `lab_metadata.json` expectations
4. Update `tools/lab_runner.py` if needed to support new lab types

