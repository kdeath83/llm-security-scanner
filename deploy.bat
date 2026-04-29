@echo off
echo ============================================
echo LLM Security Scanner - AWS CDK Deploy
echo ============================================
echo.

echo [1/5] Checking prerequisites...
python --version >nul 2>&1 || (echo Python required. Install from python.org & exit /b 1)
aws --version >nul 2>&1 || (echo AWS CLI required. Install from aws.amazon.com/cli & exit /b 1)
cdk --version >nul 2>&1 || (echo CDK required. Run: npm install -g aws-cdk & exit /b 1)

echo [2/5] Checking AWS credentials...
for /f "tokens=*" %%a in ('aws sts get-caller-identity --query Account --output text') do set ACCOUNT=%%a
for /f "tokens=*" %%a in ('aws configure get region') do set REGION=%%a
echo Deploying to Account: %ACCOUNT%, Region: %REGION%

echo [3/5] Bootstrapping CDK...
cdk bootstrap aws://%ACCOUNT%/%REGION%

echo [4/5] Installing dependencies...
cd infrastructure\simple-cdk
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

echo [5/5] Deploying...
cdk deploy --require-approval never

echo.
echo ============================================
echo DEPLOYMENT COMPLETE!
echo ============================================
echo.
echo Wait 5-10 minutes for SageMaker endpoint to be ready.
echo Then upload code to S3 and run the invoker Lambda.
echo.
pause