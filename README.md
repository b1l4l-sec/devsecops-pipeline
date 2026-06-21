#  DevSecOps Secure CI/CD Pipeline

![Pipeline](https://github.com/b1l4l-sec/devsecops-pipeline/actions/workflows/pipeline.yml/badge.svg)

A production-grade DevSecOps pipeline built with security at every stage.

##  Architecture

```
git push
    ↓
┌─────────────────────────┐
│  JOB 1: Code Security   │  → Unit Tests + Trivy FS Scan
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│  JOB 2: Docker Build    │  → Build image + Save artifact
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│  JOB 3: Container Scan  │  → Trivy vulnerability scan
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│  JOB 4: Deploy          │  → Auto deploy to production
└─────────────────────────┘
```

##  Tech Stack

| Tool | Purpose |
|------|---------|
| Flask | Python web application |
| Docker | Containerization |
| Trivy | Vulnerability scanning |
| Terraform | Infrastructure as Code |
| GitHub Actions | CI/CD automation |

##  Security Features

- ✅ Non-root container user
- ✅ Minimal base image (python:3.12-slim)
- ✅ Source code secret scanning
- ✅ Container vulnerability scanning (HIGH/CRITICAL)
- ✅ Accepted risks documented in .trivyignore
- ✅ Health checks on container

##  Pipeline Visualization

### Workflow Runs
![Workflow Runs](1%20actions.png)

### Pipeline Execution Details
![Pipeline Execution](2%20details.png)

### Security Vulnerability Scanner
![Vulnerability Scanner](3%20scannerApp.png)

### Container Scan Report
![Container Scan Report](4%20trivy%20scan.png)

##  Quick Start

### Run locally

```bash
git clone https://github.com/b1l4l-sec/devsecops-pipeline.git
cd devsecops-pipeline
docker build -t devsecops-app:1.0.0 ./app
docker run -d -p 5000:5000 devsecops-app:1.0.0
curl http://localhost:5000/health
```

### Deploy with Terraform

```bash
cd terraform
terraform init
terraform apply -auto-approve
```

### Run security scan

```bash
trivy image --severity HIGH,CRITICAL devsecops-app:1.0.0
```

##  Project Structure

```
devsecops-pipeline/
├── .github/workflows/pipeline.yml   # CI/CD pipeline
├── app/
│   ├── app.py                       # Flask application
│   ├── Dockerfile                   # Container definition
│   └── requirements.txt             # Dependencies
├── terraform/
│   ├── main.tf                      # Infrastructure
│   ├── variables.tf                 # Variables
│   └── outputs.tf                   # Outputs
├── tests/test_app.py                # Unit tests
└── .trivyignore                     # CVE exceptions
```

##  Pipeline Flow

Every git push to main automatically:
1. Runs unit tests
2. Scans source code for secrets
3. Builds Docker image
4. Scans container for HIGH/CRITICAL CVEs
5. Deploys if all security gates pass

##  Author

**b1l4l-sec**
