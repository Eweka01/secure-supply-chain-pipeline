# Secure Software Supply Chain Pipeline

A production-grade supply chain security pipeline built on AWS EKS. Every image that runs in this cluster is built, scanned, signed, attested, and policy-verified before it can be deployed. This project implements SLSA Level 2 provenance, Cosign keyless signing, CycloneDX SBOMs, Grype CVE gating, Kyverno admission control, and a live vulnerability correlation engine.

---

## Architecture Overview

<img width="2279" height="1235" alt="diagram-export-4-5-2026-5_49_32-AM" src="https://github.com/user-attachments/assets/9fe98f1d-afea-430a-b8c9-a006404ecdfa" />

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| AWS CLI | v2 | `brew install awscli` |
| Terraform | >= 1.6 | `brew install terraform` |
| kubectl | latest | `brew install kubectl` |
| Helm | >= 3 | `brew install helm` |
| Docker | latest | Docker Desktop |
| Cosign | latest | `brew install cosign` |
| Syft | latest | `brew install syft` |
| Python | 3.12 | `brew install python@3.12` |

Configure AWS credentials:
```bash
aws configure
# Region: us-east-1
# Account: 120430500058
```

---

## Project Structure

```
secure-supply-chain-pipeline/
├── app/
│   └── main.py                         # FastAPI application
├── sbom_query/
│   ├── main.py                         # SBOM vulnerability query API
│   └── requirements.txt
├── docker/
│   └── Dockerfile                      # Multi-stage, multi-platform build
├── .github/
│   └── workflows/
│       └── ci.yml                      # Full CI pipeline
├── terraform/
│   ├── main.tf                         # Provider + S3 backend
│   ├── variables.tf
│   ├── vpc.tf                          # VPC, subnets, NAT gateway
│   ├── eks.tf                          # EKS cluster + node group
│   ├── ecr.tf                          # ECR repository
│   ├── iam.tf                          # IAM roles
│   └── outputs.tf
├── helm/
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
│       ├── deployment.yaml
│       └── service.yaml
├── policies/
│   ├── policy-1-require-signed-images.yaml
│   ├── policy-2-require-slsa-provenance.yaml
│   ├── policy-3-block-critical-cves.yaml
│   └── kyverno-servicemonitor.yaml
└── requirements.txt                    # App dependencies (pinned)
```

---

## Phase 1: Run the App Locally

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

```bash
curl http://localhost:8000/health
# {"status":"healthy"}

curl http://localhost:8000/info
# {"version":"1.1.0","build_commit":"unknown","build_date":"unknown"}
```

Test build metadata injection:
```bash
BUILD_COMMIT=abc123 BUILD_DATE=2026-04-05 uvicorn app.main:app --reload
```

---

## Phase 2: Build the Docker Image Locally

```bash
# From project root
docker build -t supply-chain-app:local -f docker/Dockerfile .
docker run -p 8000:8000 supply-chain-app:local
curl http://localhost:8000/health
```

The Dockerfile uses two stages:
- **builder** — runs `pip install` on the native build platform (fast, no emulation)
- **runtime** — copies only installed packages and app code (no pip, no build tools)

`BUILD_COMMIT` and `BUILD_DATE` are injected as build args by CI so `/info` returns real values in production.

---

## Phase 3: GitHub Actions CI Setup

### GitHub Secrets

Go to: **Repo → Settings → Secrets and variables → Actions**

| Secret | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | IAM access key |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `ECR_REGISTRY` | `120430500058.dkr.ecr.us-east-1.amazonaws.com` |
| `REGISTRY_USERNAME` | `AWS` (literal string — not your repo name, not your username) |
| `REGISTRY_PASSWORD` | ECR login token (see below) |

### GitHub Variables

| Variable | Value |
|---|---|
| `AWS_REGION` | `us-east-1` |

### Setting secrets correctly (use CLI to avoid copy-paste errors)

```bash
# REGISTRY_USERNAME — always the literal string AWS, nothing else
echo "AWS" | gh secret set REGISTRY_USERNAME --repo Eweka01/secure-supply-chain-pipeline

# REGISTRY_PASSWORD — pipe directly to avoid truncation or whitespace issues
aws ecr get-login-password --region us-east-1 | gh secret set REGISTRY_PASSWORD --repo Eweka01/secure-supply-chain-pipeline
```

> **REGISTRY_PASSWORD expires every 12 hours.** Re-run the command above before triggering the provenance job if it has been more than 12 hours.
>
> **Do not set REGISTRY_USERNAME via the GitHub UI by typing** — it is easy to accidentally paste the wrong value (e.g. your repo name). Use the CLI command above to set it to exactly `AWS`.

### What the CI pipeline does

Every push to `main` triggers three jobs:

**Job 1: `build-and-push`**
1. Builds Docker image tagged with the short Git SHA (e.g. `a1b2c3d`) — never `:latest`
2. Pushes to ECR
3. Signs image by digest using Cosign keyless mode (GitHub OIDC)
4. Verifies the signature immediately
5. Generates a CycloneDX SBOM with Syft
6. Scans the SBOM with Grype — fails the pipeline if any Critical CVE is found
7. Attests the SBOM to the image in ECR using `cosign attest --type cyclonedx` — required by Policy 3
8. Uploads SBOM as a GitHub Actions artifact (retained 90 days)
9. Uploads SBOM to S3 keyed by image digest

**Job 2: `provenance`**
- Calls the official SLSA GitHub Generator reusable workflow
- Generates an in-toto provenance attestation signed by the SLSA framework (not your pipeline)
- Attaches attestation to the image in ECR
- This is what qualifies as SLSA Level 2

**Job 3: `verify-provenance`**
- Downloads and prints the provenance JSON to the workflow logs
- Verifies the attestation using `cosign verify-attestation`

---

## Phase 4: AWS Infrastructure with Terraform

### Step 1: Create the Terraform state backend (one-time)

```bash
aws s3 mb s3://supply-chain-tfstate-120430500058-use1 --region us-east-1
aws s3api put-bucket-versioning \
  --bucket supply-chain-tfstate-120430500058-use1 \
  --versioning-configuration Status=Enabled
```

### Step 2: Apply infrastructure

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

This creates:
- VPC (`10.0.0.0/16`) with 2 public and 2 private subnets across 2 AZs
- NAT gateway for private subnet outbound access
- EKS cluster (`supply-chain-cluster`, v1.31) with nodes in private subnets
- Managed node group: 2x `t3.medium` (min 1, max 3)
- ECR repository (`supply-chain-app`) with mutable tags, scan on push, 10-image lifecycle policy
- IAM roles for cluster and nodes

### Step 3: Connect to the cluster

```bash
aws eks update-kubeconfig --region us-east-1 --name supply-chain-cluster
kubectl get nodes
```

> **If resources already exist:** Import them into state instead of recreating:
> ```bash
> terraform import aws_ecr_repository.app supply-chain-app
> terraform import aws_iam_role.cluster supply-chain-cluster-cluster-role
> terraform import aws_iam_role.nodes supply-chain-cluster-node-role
> terraform import aws_eks_cluster.main supply-chain-cluster
> ```

---

## Phase 5: Deploy the Application with Helm

### Update the image digest

Before deploying, get the latest app image digest from ECR:

```bash
aws ecr describe-images --repository-name supply-chain-app --region us-east-1 \
  --query 'sort_by(imageDetails,&imagePushedAt)[*].{digest:imageDigest,tags:imageTags}' \
  --output json
```

Find the entry with a short SHA tag (e.g. `["a1b2c3d"]`) — that is the app image. Copy its digest.

> **Important:** Do not use entries tagged `.sig` or `.att` — those are the Cosign signature and SLSA attestation objects, not the app image.

Update `helm/values.yaml`:
```yaml
image:
  digest: sha256:<digest-of-the-app-image>
```

### Deploy

```bash
# From project root
helm install supply-chain-app ./helm -n supply-chain --create-namespace
kubectl get pods -n supply-chain
```

### Upgrade after a new image is pushed

```bash
helm upgrade supply-chain-app ./helm -n supply-chain \
  --set image.digest=sha256:<new-digest>
```

---

## Phase 6: Kyverno Policy Enforcement

### Install Kyverno

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
kubectl get pods -n kyverno
```

Wait for all 4 pods to reach `1/1 Running`.

### EKS networking fix (required for private node groups)

Kyverno runs admission webhooks that the EKS API server must reach on port 9443. Add security group rules and VPC endpoints to allow this:

```bash
# Get cluster security group
SG_ID=$(aws eks describe-cluster --name supply-chain-cluster --region us-east-1 \
  --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId' --output text)

# Allow webhook traffic within the cluster security group
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID --protocol tcp --port 443 \
  --source-group $SG_ID --region us-east-1

aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID --protocol tcp --port 9443 \
  --source-group $SG_ID --region us-east-1
```

```bash
# Get EKS cluster VPC and private subnets
VPC_ID=$(aws eks describe-cluster --name supply-chain-cluster --region us-east-1 \
  --query 'cluster.resourcesVpcConfig.vpcId' --output text)

PRIVATE_SUBNETS=$(aws ec2 describe-subnets --region us-east-1 \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=mapPublicIpOnLaunch,Values=false" \
  --query 'Subnets[*].SubnetId' --output text)

# Create VPC endpoints so Kyverno can reach ECR for signature verification
aws ec2 create-vpc-endpoint --vpc-id $VPC_ID \
  --service-name com.amazonaws.us-east-1.ecr.api \
  --vpc-endpoint-type Interface \
  --subnet-ids $PRIVATE_SUBNETS \
  --security-group-ids $SG_ID \
  --private-dns-enabled --region us-east-1

aws ec2 create-vpc-endpoint --vpc-id $VPC_ID \
  --service-name com.amazonaws.us-east-1.ecr.dkr \
  --vpc-endpoint-type Interface \
  --subnet-ids $PRIVATE_SUBNETS \
  --security-group-ids $SG_ID \
  --private-dns-enabled --region us-east-1

ROUTE_TABLES=$(aws ec2 describe-route-tables --region us-east-1 \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'RouteTables[*].RouteTableId' --output text)

aws ec2 create-vpc-endpoint --vpc-id $VPC_ID \
  --service-name com.amazonaws.us-east-1.s3 \
  --vpc-endpoint-type Gateway \
  --route-table-ids $ROUTE_TABLES --region us-east-1
```

### Fix Kyverno webhook timeout

The default 10s webhook timeout is too short for image signature verification (which needs to call Rekor). Increase it to 30s:

```bash
kubectl patch deployment kyverno-admission-controller -n kyverno --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--webhookTimeout=30"}]'

kubectl rollout status deployment kyverno-admission-controller -n kyverno
```

### Apply policies

```bash
kubectl apply -f policies/policy-1-require-signed-images.yaml
kubectl apply -f policies/policy-2-require-slsa-provenance.yaml
kubectl apply -f policies/policy-3-block-critical-cves.yaml

# Verify all three are Ready
kubectl get clusterpolicy
```

Expected output:
```
NAME                      ADMISSION   BACKGROUND   READY   AGE
block-critical-cves       true        false        True    ...
require-signed-images     true        false        True    ...
require-slsa-provenance   true        false        True    ...
```

Test rejection:
```bash
kubectl run test-unsigned --image=nginx:latest -n supply-chain
# Expected: admission webhook denied — Only images from 120430500058... are allowed
```

> **Policy 3 requires SBOM attestation.** The `cosign attest` step in CI attaches the SBOM to the image in ECR. Policy 3 will block any image that was built before this step was added to the pipeline. Re-run CI to produce a compliant image.

---

## Phase 7: SBOM Vulnerability Correlation Engine

### Setup

```bash
# Create S3 bucket for SBOM storage (one-time)
aws s3 mb s3://supply-chain-sboms-120430500058 --region us-east-1
aws s3api put-bucket-versioning \
  --bucket supply-chain-sboms-120430500058 \
  --versioning-configuration Status=Enabled

# Upload an existing SBOM manually (CI does this automatically going forward)
DIGEST=<your-app-image-digest-without-sha256:>
aws s3 cp sbom.json \
  s3://supply-chain-sboms-120430500058/sboms/supply-chain-app/${DIGEST}/sbom.cyclonedx.json

# Install and start the query service
pip install -r sbom_query/requirements.txt
uvicorn sbom_query.main:app --port 8001 --reload
```

### Query examples

```bash
# Find all images containing a package
curl http://localhost:8001/query?package=fastapi

# Find all images with a specific CVE
curl http://localhost:8001/query?cve=CVE-2024-1234

# List all indexed SBOMs
curl http://localhost:8001/sboms
```

Example response:
```json
{
  "query": {"package": "fastapi", "cve": null},
  "total_images_scanned": 1,
  "affected_images": 1,
  "results": [{
    "image": "supply-chain-app",
    "digest": "sha256:f00b0fe1...",
    "match": {
      "name": "fastapi",
      "version": "0.115.0",
      "type": "library",
      "purl": "pkg:pypi/fastapi@0.115.0"
    }
  }]
}
```

---

## Phase 8: Grafana Dashboard

### Install Prometheus and Grafana

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  -n monitoring --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
  --set grafana.adminPassword=admin \
  --set grafana.service.type=ClusterIP

kubectl rollout status deployment kube-prometheus-stack-grafana -n monitoring
```

### Apply Kyverno ServiceMonitor

```bash
kubectl apply -f policies/kyverno-servicemonitor.yaml
```

> The ServiceMonitor must be in the `kyverno` namespace (not `monitoring`) and the port name is `metrics-port`.

### Access Grafana

```bash
kubectl port-forward svc/kube-prometheus-stack-grafana 3000:80 -n monitoring
```

Open [http://localhost:3000](http://localhost:3000)

Default login: `admin` / `admin`

> If login fails, reset the password:
> ```bash
> kubectl exec -n monitoring \
>   $(kubectl get pod -n monitoring -l app.kubernetes.io/name=grafana -o jsonpath='{.items[0].metadata.name}') \
>   -c grafana -- grafana cli admin reset-admin-password <newpassword>
> ```

### Key Prometheus queries for the dashboard

| Panel | Query |
|---|---|
| Allowed requests | `sum(rate(kyverno_admission_requests_total{request_allowed="true"}[5m]))` |
| Blocked requests | `sum(rate(kyverno_admission_requests_total{request_allowed="false"}[5m]))` |
| Image verify pass | `sum(rate(kyverno_policy_results_total{rule_type="imageVerify",rule_result="pass"}[5m]))` |
| Image verify fail | `sum(rate(kyverno_policy_results_total{rule_type="imageVerify",rule_result="fail"}[5m]))` |
| Policy results by rule | `sum(kyverno_policy_results_total) by (rule_name, rule_result)` |
| Webhook latency p99 | `histogram_quantile(0.99, sum(rate(kyverno_admission_review_duration_seconds_bucket[5m])) by (le))` |

---

## Verify the Signatures

```bash
IMAGE=120430500058.dkr.ecr.us-east-1.amazonaws.com/supply-chain-app@sha256:<digest>

# Verify Cosign signature
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/Eweka01/.*" \
  $IMAGE

# Verify SBOM attestation (CycloneDX)
cosign verify-attestation \
  --type cyclonedx \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/Eweka01/.*" \
  $IMAGE

# Verify SLSA provenance attestation
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/slsa-framework/.*" \
  $IMAGE
```

---

## Generate SBOM Locally

```bash
# Run Syft against local image
syft supply-chain-app:local -o cyclonedx-json > sbom.json

# Query it directly
cat sbom.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
comps = [c for c in data['components'] if c.get('purl','').startswith('pkg:pypi')]
for c in comps:
    print(c['name'], c['version'])
"
```

---

## Key Design Decisions

| Decision | Reason |
|---|---|
| Images tagged by Git SHA, never `:latest` | Every image maps to exactly one commit — traceability |
| Images referenced by digest in Helm | Tags are mutable; digests are content-addressable and immutable |
| Dependencies pinned in `requirements.txt` | Unpinned versions produce different SBOMs on every build |
| Sign by digest, not by tag | Signing a tag is meaningless if the tag can be moved |
| SBOM attested to image (not just uploaded to S3) | Policy 3 checks ECR attestations at admission time — S3 alone is not verifiable by Kyverno |
| ECR tags set to MUTABLE | `cosign attest` and SLSA generator both write to the `.att` tag — immutable tags block the second write permanently. Security comes from digest references, not tag immutability |
| SLSA provenance in a separate job | Provenance generated by external workflow = SLSA Level 2 |
| Kyverno webhook timeout set to 30s | Signature verification (Rekor + ECR) takes >10s from private subnets |
| VPC endpoints for ECR | Avoids internet roundtrip from private nodes; faster and more reliable |
| ServiceMonitor in `kyverno` namespace | Prometheus discovers ServiceMonitors across namespaces correctly |

---

## Troubleshooting

**SLSA provenance job exits with code 27 (repeatedly)**
Check the provenance job inputs in the GitHub Actions log. Expand the job and look at the `Inputs` section at the top:
```
registry-username: ← must show AWS here, not empty
registry-password: *** ← must not be empty
```
If `registry-username` is empty, the `REGISTRY_USERNAME` secret is missing or was never set. Fix:
```bash
echo "AWS" | gh secret set REGISTRY_USERNAME --repo Eweka01/secure-supply-chain-pipeline
aws ecr get-login-password --region us-east-1 | gh secret set REGISTRY_PASSWORD --repo Eweka01/secure-supply-chain-pipeline
```
> `REGISTRY_USERNAME` is always the literal string `AWS` — not your GitHub username, not your repo name.

**`no basic auth credentials` when pushing to ECR**
The `REGISTRY_PASSWORD` secret has expired. Regenerate:
```bash
aws ecr get-login-password --region us-east-1
```
Update the GitHub secret with the new value.

**Kyverno webhook `context deadline exceeded`**
The `--webhookTimeout=30` flag may have been lost after a Kyverno upgrade. Re-apply:
```bash
kubectl patch deployment kyverno-admission-controller -n kyverno --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--webhookTimeout=30"}]'
```

**`CreateContainerError` on app pods**
The digest in `helm/values.yaml` is pointing to a Cosign signature (`.sig`) or SLSA attestation (`.att`) object instead of the app image. Check ECR and use only the digest tagged with the short SHA.

**`AccessDenied` uploading SBOM to S3 in CI**
The IAM user `github-action-supply-chain` needs `s3:PutObject` on the SBOM bucket. Add the inline policy:
```bash
aws iam put-user-policy \
  --user-name github-action-supply-chain \
  --policy-name sbom-s3-upload \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:PutObject","s3:GetObject","s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::supply-chain-sboms-120430500058",
        "arn:aws:s3:::supply-chain-sboms-120430500058/*"
      ]
    }]
  }'
```

**SLSA provenance job fails with `TAG_INVALID` — `.att` tag already exists**
`cosign attest` (SBOM) and the SLSA generator both write to the same `.att` tag suffix in ECR. With immutable tags enabled, the second write always fails. The permanent fix is to set ECR tags to mutable — image integrity is enforced by digest references in Helm and Kyverno, not by tag immutability:
```bash
aws ecr put-image-tag-mutability \
  --repository-name supply-chain-app \
  --image-tag-mutability MUTABLE \
  --region us-east-1
```
This is already set in `terraform/ecr.tf`.

**Terraform `AccessDenied` on S3**
The bucket name may be owned by another AWS account. Use account-ID-suffixed names:
```bash
aws s3 mb s3://supply-chain-tfstate-<account-id>-use1 --region us-east-1
```

**Kyverno `No data` in Grafana**
Verify the ServiceMonitor is in the `kyverno` namespace and the port name is `metrics-port`:
```bash
kubectl get servicemonitor -n kyverno
kubectl port-forward svc/kube-prometheus-stack-prometheus 9090:9090 -n monitoring
curl -s "http://localhost:9090/api/v1/targets?state=active" | python3 -c \
  "import json,sys; [print(t['labels']['service'], t['health']) for t in json.load(sys.stdin)['data']['activeTargets'] if 'kyverno' in str(t['labels'])]"
```

---

## Demo Walkthrough

### Before you record
- Split terminal: commands on the left, output on the right
- Browser tabs ready: GitHub Actions, AWS ECR console, Grafana
- Port-forwards running:
  ```bash
  kubectl port-forward svc/kube-prometheus-stack-grafana 3000:80 -n monitoring &
  kubectl port-forward svc/kube-prometheus-stack-prometheus 9090:9090 -n monitoring &
  ```
- Confirm app is live: `kubectl get pods -n supply-chain`

---

### Scene 1 — Trigger the pipeline (1 min)
Make a small change and push:
```bash
# Edit app/main.py, then:
git add app/main.py
git commit -m "demo: trigger pipeline"
git push origin main
```
Switch to GitHub Actions → show the 3 jobs queuing: `build-and-push`, `provenance`, `verify-provenance`.

---

### Scene 2 — Walk the CI steps (2 min)
Click into `build-and-push` and expand each step:

| Step | Talking point |
|---|---|
| Build & push | "Tagged with short Git SHA — never :latest" |
| Sign container | "Cosign signs by digest using GitHub OIDC — no long-lived keys" |
| Generate SBOM | "Full ingredient list of every OS and Python package inside the image" |
| Grype scan | "Pipeline fails here automatically if any Critical CVE is found" |
| Attest SBOM | "SBOM is cryptographically attached to the image in ECR" |
| Upload to S3 | "Enables the vulnerability correlation engine" |

Click into `provenance` → show the attestation JSON in the logs (builder ID, source repo, commit SHA).

---

### Scene 3 — ECR console (45 sec)
Open AWS ECR → `supply-chain-app` → click the latest digest. Show the 4 objects:
- `:f8453db` — app image
- `.sig` — Cosign signature
- `.att` — SBOM attestation
- `.att` — SLSA provenance

> "Every artifact is cryptographically linked to this exact build."

---

### Scene 4 — Kyverno blocks a bad image (1 min)
```bash
kubectl run bad-pod --image=nginx:latest -n supply-chain
```
Expected output:
```
Error from server: admission webhook denied the request:
block-non-ecr-images: Only images from 120430500058.dkr.ecr.us-east-1.amazonaws.com are allowed
```
> "Kyverno intercepts every pod before it starts — no exceptions."

---

### Scene 5 — Grafana dashboard (1 min)
Open [http://localhost:3000/d/supply-chain-security](http://localhost:3000/d/supply-chain-security)

Point out:
- **Admission Requests** — the blocked `nginx:latest` attempt just registered
- **Total Blocked** stat — red if any violations
- **Image Verification Results** — pass/fail from the `imageVerify` rule
- **Webhook Latency p99** — Kyverno overhead per admission

---

### Scene 6 — SBOM query engine (45 sec)
```bash
# Which images contain fastapi?
curl -s "http://localhost:8001/query?package=fastapi" | python3 -m json.tool

# Which images are affected by a CVE?
curl -s "http://localhost:8001/query?cve=CVE-2024-1234" | python3 -m json.tool
```
> "Ask any CVE — instantly know which images in production are affected."

---

### Scene 7 — Close (30 sec)
Show the architecture diagram. Summarise:
> "Code to signed, attested, policy-verified running pod — every step automated and cryptographically auditable."

---

### Recording tips
- Use **QuickTime** (screen record) + **Loom** or **OBS** for voiceover
- Keep total length under **8 minutes**
- Zoom terminal font to **18–20pt** so text is readable on video
- Pause 2 seconds after each command output before moving on

---

## AWS Resources Created

| Resource | Name | Notes |
|---|---|---|
| EKS Cluster | `supply-chain-cluster` | v1.31, us-east-1 |
| Node Group | `supply-chain-cluster-nodes` | 2x t3.medium, private subnets |
| ECR Repository | `supply-chain-app` | Mutable tags, scan on push |
| S3 (Terraform state) | `supply-chain-tfstate-120430500058-use1` | Versioned |
| S3 (SBOMs) | `supply-chain-sboms-120430500058` | Keyed by image digest |
| VPC | `supply-chain-cluster-vpc` | 10.0.0.0/16 |
