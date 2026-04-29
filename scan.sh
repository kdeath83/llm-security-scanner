#!/bin/bash
# Scan a file using the LLM Security Scanner (FIXED VERSION)
set -e

# Check arguments
if [ -z "$1" ]; then
    echo "Usage: ./scan.sh <file-to-scan.py>"
    echo "Example: ./scan.sh myapp.py"
    exit 1
fi

FILE=$1

# Check file exists
if [ ! -f "$FILE" ]; then
    echo "ERROR: File not found: $FILE"
    exit 1
fi

# Check file size (100KB limit)
FILE_SIZE=$(stat -f%z "$FILE" 2>/dev/null || stat -c%s "$FILE" 2>/dev/null)
if [ "$FILE_SIZE" -gt 100000 ]; then
    echo "ERROR: File too large (${FILE_SIZE} bytes). Max: 100KB"
    exit 1
fi

# Get stack info
echo "Getting deployment info..."
ACCOUNT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || {
    echo "ERROR: AWS credentials not configured"
    exit 1
}

REGION=$(aws configure get region)
BUCKET="llm-security-scanner-$ACCOUNT-$REGION"
LAMBDA="llama-security-scanner-ScannerLambda"

# Check if stack exists
echo "Checking deployment..."
if ! aws cloudformation describe-stacks --stack-name LLMSecurityScannerStack --query 'Stacks[0].StackStatus' --output text >/dev/null 2>&1; then
    echo "ERROR: Stack not found. Deploy first with: ./deploy.sh"
    exit 1
fi

# Check endpoint status
echo "Checking SageMaker endpoint..."
ENDPOINT_STATUS=$(aws sagemaker describe-endpoint --endpoint-name llama-security-scanner --query 'EndpointStatus' --output text 2>/dev/null) || {
    echo "ERROR: Endpoint not found. Deployment may still be in progress."
    exit 1
}

if [ "$ENDPOINT_STATUS" != "InService" ]; then
    echo "⚠️  Endpoint status: $ENDPOINT_STATUS"
    echo "Waiting for endpoint to be ready (this may take 5-10 minutes)..."
    echo "Check manually: aws sagemaker describe-endpoint --endpoint-name llama-security-scanner"
    exit 1
fi

echo "✓ Endpoint is ready"

# Upload to S3
echo "Uploading $FILE to S3..."
REMOTE_KEY="uploads/$(basename $FILE)"
aws s3 cp "$FILE" "s3://$BUCKET/$REMOTE_KEY" || {
    echo "ERROR: Failed to upload file"
    exit 1
}

# Invoke Lambda
echo "Analyzing with LLM (this takes 30-60 seconds)..."
PAYLOAD=$(jq -n --arg bucket "$BUCKET" --arg key "$REMOTE_KEY" '{bucket: $bucket, key: $key}')

# Create temp file for response
RESPONSE_FILE=$(mktemp)
trap "rm -f $RESPONSE_FILE" EXIT

aws lambda invoke \
    --function-name "$LAMBDA" \
    --payload "$PAYLOAD" \
    "$RESPONSE_FILE" || {
    echo "ERROR: Lambda invocation failed"
    exit 1
}

# Check for Lambda errors
if grep -q '"errorType"' "$RESPONSE_FILE" 2>/dev/null; then
    echo "ERROR: Lambda execution failed:"
    cat "$RESPONSE_FILE" | jq -r '.errorMessage' 2>/dev/null || cat "$RESPONSE_FILE"
    exit 1
fi

# Parse response
RESULTS_KEY=$(cat "$RESPONSE_FILE" | jq -r '.results_key // empty')
VULN_COUNT=$(cat "$RESPONSE_FILE" | jq -r '.vulnerability_count // 0')
RISK_SCORE=$(cat "$RESPONSE_FILE" | jq -r '.risk_score // 0')

if [ -z "$RESULTS_KEY" ]; then
    echo "ERROR: No results key in response"
    cat "$RESPONSE_FILE"
    exit 1
fi

echo ""
echo "============================================"
echo "SCAN COMPLETE"
echo "============================================"
echo ""
echo "Vulnerabilities found: $VULN_COUNT"
echo "Risk score: $RISK_SCORE/100"
echo ""

# Download and display results
echo "Downloading detailed results..."
LOCAL_RESULTS="$(basename $FILE).security.json"
aws s3 cp "s3://$BUCKET/$RESULTS_KEY" "$LOCAL_RESULTS" || {
    echo "WARNING: Could not download results from S3"
    echo "View online: s3://$BUCKET/$RESULTS_KEY"
    exit 0
}

echo ""
echo "Results saved to: $LOCAL_RESULTS"
echo ""

# Summary
echo "Vulnerability Summary:"
jq -r '.vulnerabilities[] | "  [\(.severity | ascii_upcase)] \(.type): \(.description[0:60])..."' "$LOCAL_RESULTS" 2>/dev/null || echo "  (No vulnerabilities found or parse error)"

echo ""
echo "Full results: $LOCAL_RESULTS"