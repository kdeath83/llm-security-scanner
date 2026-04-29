#!/bin/bash
# Scan a file using the deployed LLM Security Scanner

if [ -z "$1" ]; then
    echo "Usage: ./scan.sh <file-to-scan.py>"
    exit 1
fi

FILE=$1
BUCKET=$(aws cloudformation describe-stacks --stack-name LLMSecurityScannerStack --query 'Stacks[0].Outputs[?OutputKey==`BucketName`].OutputValue' --output text)
PARSER=$(aws cloudformation describe-stacks --stack-name LLMSecurityScannerStack --query 'Stacks[0].Outputs[?OutputKey==`ParserLambda`].OutputValue' --output text)

# Upload to S3
echo "Uploading $FILE to S3..."
aws s3 cp "$FILE" "s3://$BUCKET/uploads/$(basename $FILE)"

# Trigger parser
echo "Parsing code..."
aws lambda invoke --function-name "$PARSER" --payload "{\"bucket\":\"$BUCKET\",\"key\":\"uploads/$(basename $FILE)\"}" /tmp/parse-response.json

# Get results location
RESULTS_KEY=$(cat /tmp/parse-response.json | jq -r '.results_key')
echo "Analysis complete. Results at: s3://$BUCKET/$RESULTS_KEY"

# Download results
aws s3 cp "s3://$BUCKET/$RESULTS_KEY" "$(basename $FILE).security-results.json"
echo "Results saved to: $(basename $FILE).security-results.json"