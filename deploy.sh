#!/bin/bash
# One-Click Deploy Script for LLM Security Scanner (FIXED VERSION)
set -e  # Exit on any error

echo "============================================"
echo "LLM Security Scanner - AWS CDK Deploy"
echo "============================================"
echo ""

# Check prerequisites
echo "[1/5] Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || { echo "ERROR: Python 3 required. Install from python.org"; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "ERROR: AWS CLI required. Install from aws.amazon.com/cli"; exit 1; }
command -v cdk >/dev/null 2>&1 || { echo "ERROR: AWS CDK required. Run: npm install -g aws-cdk"; exit 1; }

# Check AWS credentials
echo "[2/5] Checking AWS credentials..."
if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "ERROR: AWS credentials not configured. Run: aws configure"
    exit 1
fi
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REGION=$(aws configure get region)
echo "Deploying to Account: $ACCOUNT, Region: $REGION"

# Bootstrap CDK if needed
echo "[3/5] Bootstrapping CDK..."
cdk bootstrap aws://$ACCOUNT/$REGION || {
    echo "WARNING: CDK bootstrap failed or already exists, continuing..."
}

# Install dependencies
echo "[4/5] Installing Python dependencies..."
cd infrastructure/simple-cdk
python3 -m pip install --quiet aws-cdk-lib constructs boto3 || {
    echo "ERROR: Failed to install dependencies"
    exit 1
}

# Deploy
echo "[5/5] Deploying stack (this takes 10-15 minutes)..."
cdk deploy --require-approval never || {
    echo "ERROR: Deployment failed"
    exit 1
}

echo ""
echo "============================================"
echo "DEPLOYMENT COMPLETE!"
echo "============================================"
echo ""
echo "⚠️  IMPORTANT: SageMaker endpoint is starting..."
echo "   Wait 5-10 minutes before scanning."
echo ""
echo "Check endpoint status:"
echo "  aws sagemaker describe-endpoint --endpoint-name llama-security-scanner"
echo ""
echo "When endpoint shows 'Status': 'InService', run:"
echo "  ./scan.sh mycode.py"
echo ""
echo "View results:"
echo "  aws s3 ls s3://llm-security-scanner-$ACCOUNT-$REGION/results/"