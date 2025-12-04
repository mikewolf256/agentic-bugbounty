# Agentic Bug Bounty Makefile

.PHONY: help install test lint mcp labs test-labs clean

# Default target
help:
	@echo "Agentic Bug Bounty - Available targets:"
	@echo ""
	@echo "  install      - Install Python dependencies"
	@echo "  mcp          - Start MCP server"
	@echo "  test         - Run tests"
	@echo "  lint         - Run linters"
	@echo ""
	@echo "Lab targets:"
	@echo "  labs         - List available labs"
	@echo "  test-labs    - Run all labs and validate detection"
	@echo "  lab-xss      - Run XSS lab test"
	@echo "  lab-idor     - Run IDOR lab test"
	@echo "  lab-secrets  - Run secrets exposure lab test"
	@echo ""
	@echo "  clean        - Clean up output files"

# Install dependencies
install:
	pip install -r requirements.txt

# Start MCP server
mcp:
	python mcp_zap_server.py

# Run tests
test:
	python -m pytest tests/ -v

# Run linters
lint:
	python -m flake8 *.py tools/*.py --max-line-length=120

# List available labs
labs:
	python tools/lab_runner.py --list

# Run all labs and validate
test-labs: test-lab-xss test-lab-idor test-lab-secrets
	@echo ""
	@echo "========================================"
	@echo "All lab tests completed!"
	@echo "========================================"

# Individual lab tests
test-lab-xss:
	@echo "========================================"
	@echo "Testing XSS Basic Lab"
	@echo "========================================"
	python tools/lab_runner.py --lab xss-basic --full --profile xss-heavy

test-lab-idor:
	@echo "========================================"
	@echo "Testing IDOR API Lab"
	@echo "========================================"
	python tools/lab_runner.py --lab idor-api --full --profile bac-heavy

test-lab-secrets:
	@echo "========================================"
	@echo "Testing Secrets Exposure Lab"
	@echo "========================================"
	python tools/lab_runner.py --lab secrets-exposure --full --profile recon-only

# Start a specific lab (use: make start-lab LAB=xss-basic)
start-lab:
	python tools/lab_runner.py --lab $(LAB) --start

# Stop a specific lab
stop-lab:
	python tools/lab_runner.py --lab $(LAB) --stop

# Scan a specific lab
scan-lab:
	python tools/lab_runner.py --lab $(LAB) --scan

# Full scan with default profile
full-scan:
	python agentic_runner.py --mode full-scan

# Full scan with profile
full-scan-profile:
	python agentic_runner.py --mode full-scan --profile $(PROFILE)

# List profiles
profiles:
	python agentic_runner.py --list-profiles

# Clean output files
clean:
	rm -rf output_zap/*.json
	rm -rf output_zap/*.md
	rm -rf output_zap/artifacts/
	rm -rf output_zap/host_history/
	rm -f scope.lab.*.json
	@echo "Cleaned output files"

# Clean lab containers
clean-labs:
	cd labs/xss-basic && docker-compose down --rmi local 2>/dev/null || true
	cd labs/idor-api && docker-compose down --rmi local 2>/dev/null || true
	cd labs/secrets-exposure && docker-compose down --rmi local 2>/dev/null || true
	@echo "Cleaned lab containers"

# Docker build MCP server
docker-build:
	docker build -f Dockerfile.mcp -t agentic-mcp .

# Docker run MCP server
docker-run:
	docker run -p 8000:8000 -v $(PWD)/output_zap:/app/output_zap agentic-mcp

