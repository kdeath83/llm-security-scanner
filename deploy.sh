#!/bin/bash
# One-Click Deploy Script for LLM Security Scanner
echo "============================================"
echo "LLM Security Scanner - AWS CDK Deploy"
echo "============================================"
echo ""

# Check prerequisites
echo "[1/5] Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || { echo "Python 3 required. Install: https://python.org"; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "AWS CLI required. Install: https://aws.amazon.com/cli/"; exit 1; }
command -v cdk >/dev/null 2>&1 || { echo "AWS CDK required. Install: npm install -g aws-cdk"; exit 1; }

# Check AWS credentials
echo "[2/5] Checking AWS credentials..."
aws sts get-caller-identity >/dev/null 2>&1 || { echo "AWS credentials not configured. Run: aws configure"; exit 1; }
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
echo "Deploying to Account: $ACCOUNT, Region: $REGION"

# Bootstrap CDK
echo "[3/5] Bootstrapping CDK..."
cdk bootstrap aws://$ACCOUNT/$REGION

# Install dependencies
echo "[4/5] Installing Python dependencies..."
cd infrastructure/simple-cdk
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Deploy
echo "[5/5] Deploying stack..."
cdk deploy --require-approval never

echo ""
echo "============================================"
echo "DEPLOYMENT COMPLETE!"
echo "============================================"
echo ""
echo "Next steps:"
echo "1. Wait 5-10 minutes for SageMaker endpoint to be ready"
echo "2. Upload code to scan: ./scan.sh mycode.py"
echo "3. Check results in S3 bucket"
echo ""
echo "To trigger a scan:"
echo "  aws lambda invoke --function-name llm-security-invoker --payload '{\"bucket\":\"YOUR_BUCKET\",\"key\":\"uploads/mycode.py\"}' response.json"