# LLM Security Scanner

One-click AWS deployment of a cost-optimized code security analyzer using self-hosted Llama 3.1 (8B) on SageMaker.

## Cost: ~$200-400/month vs $3,000+ for Bedrock API

## Quick Deploy

```bash
git clone https://github.com/kdeath83/llm-security-scanner
cd llm-security-scanner
./deploy.sh
```

**Or on Windows:**
```batch
deploy.bat
```

## What Gets Deployed

| Component | Service | Cost |
|-----------|---------|------|
| LLM Engine | SageMaker Serverless (Llama 3.1 8B) | ~$200-400/mo |
| Storage | S3 | ~$5-20/mo |
| Orchestration | Lambda | ~$10-30/mo |
| **Total** | | **~$250-500/mo** |

## Usage

```bash
# Scan a Python file
./scan.sh myapp.py

# Results saved as myapp.py.security-results.json
```

## Architecture

- **SageMaker Serverless**: Llama 3.1 8B scales to zero when idle (saves 70% vs always-on)
- **Lambda**: Code parsing and LLM invocation
- **S3**: Code uploads and SARIF results
- **No OpenSearch**: Uses simple S3 + Lambda to minimize costs

## Requirements

- AWS CLI configured
- CDK installed: `npm install -g aws-cdk`
- Python 3.11+

## Next Steps

After deployment:
1. Wait 5-10 min for SageMaker endpoint
2. Test with: `./scan.sh testfile.py`
3. Integrate with CodePipeline for CI/CD

## License

MIT