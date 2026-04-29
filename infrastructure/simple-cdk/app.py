"""
CDK Deployment Script - One Click Deploy
"""
import aws_cdk as cdk
from constructs import Construct
from aws_cdk import (
    Stack, RemovalPolicy, Duration,
    aws_sagemaker as sagemaker,
    aws_lambda as lambda_,
    aws_s3 as s3,
    aws_iam as iam,
    aws_ec2 as ec2,
    CfnOutput
)

class LLMSecurityScannerStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # VPC
        vpc = ec2.Vpc(self, "ScannerVPC", max_azs=2, nat_gateways=1)
        
        # S3 Bucket
        bucket = s3.Bucket(self, "ScannerBucket",
            bucket_name=f"llm-security-scanner-{self.account}-{self.region}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.RETAIN
        )
        
        # SageMaker Role
        sagemaker_role = iam.Role(self, "SageMakerRole",
            assumed_by=iam.ServicePrincipal("sagemaker.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerFullAccess")
            ]
        )
        bucket.grant_read_write(sagemaker_role)
        
        # SageMaker Model (Llama 3.1 8B from JumpStart)
        model = sagemaker.CfnModel(self, "LlamaSecurityModel",
            model_name="llama-3-1-8b-security",
            execution_role_arn=sagemaker_role.role_arn,
            containers=[{
                "image": f"{self.account}.dkr.ecr.{self.region}.amazonaws.com/jumpstart-runtime:latest",
                "modelDataUrl": f"s3://jumpstart-cache-prod-{self.region}/meta-textgeneration/meta-textgeneration-llama-3-1-8b-instruct/artifacts/inference-prepack/v1.0.0/",
                "environment": {
                    "SAGEMAKER_PROGRAM": "inference.py",
                    "SAGEMAKER_SUBMIT_DIRECTORY": "/opt/ml/model/code"
                }
            }]
        )
        
        # Endpoint Config with Serverless for cost optimization
        endpoint_config = sagemaker.CfnEndpointConfig(self, "EndpointConfig",
            endpoint_config_name="llama-8b-serverless",
            production_variants=[{
                "variantName": "AllTraffic",
                "modelName": model.model_name,
                "serverlessConfig": {
                    "maxConcurrency": 50,
                    "memorySizeInMb": 4096
                }
            }]
        )
        
        endpoint = sagemaker.CfnEndpoint(self, "LlamaEndpoint",
            endpoint_name="llama-security-scanner",
            endpoint_config_name=endpoint_config.endpoint_config_name
        )
        
        # Lambda - Code Parser
        parser_role = iam.Role(self, "ParserRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")]
        )
        bucket.grant_read_write(parser_role)
        
        parser_fn = lambda_.Function(self, "CodeParser",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline("""
import json
import boto3
import os

def handler(event, context):
    s3 = boto3.client('s3')
    bucket = event['bucket']
    key = event['key']
    
    # Download and parse code
    response = s3.get_object(Bucket=bucket, Key=key)
    code = response['Body'].read().decode('utf-8')
    
    # Simple chunking (can be improved with AST)
    chunks = []
    lines = code.split('\\n')
    chunk = []
    for line in lines:
        chunk.append(line)
        if len(chunk) > 50:  # 50 lines per chunk
            chunks.append('\\n'.join(chunk))
            chunk = []
    if chunk:
        chunks.append('\\n'.join(chunk))
    
    return {
        'chunks': chunks,
        'bucket': bucket,
        'original_key': key
    }
"""),
            timeout=Duration.minutes(5),
            memory_size=2048,
            environment={"BUCKET_NAME": bucket.bucket_name}
        )
        
        # Lambda - LLM Invoker
        invoker_role = iam.Role(self, "InvokerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")]
        )
        invoker_role.add_to_policy(iam.PolicyStatement(
            actions=["sagemaker:InvokeEndpoint"],
            resources=[endpoint.attr_endpoint_arn]
        ))
        
        invoker_fn = lambda_.Function(self, "LLMInvoker",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_inline(f"""
import json
import boto3
import os

sm = boto3.client('sagemaker-runtime')
ENDPOINT = os.environ['ENDPOINT_NAME']

def handler(event, context):
    results = []
    for chunk in event['chunks']:
        prompt = f\"\"\"Analyze this code for security vulnerabilities. Output JSON with findings list having severity, line, description, fix.

Code:
{{chunk}}

JSON:"\"\"\"
        
        response = sm.invoke_endpoint(
            EndpointName=ENDPOINT,
            ContentType='application/json',
            Body=json.dumps({{
                'inputs': prompt,
                'parameters': {{'max_new_tokens': 1000, 'temperature': 0.1}}
            }})
        )
        
        result = json.loads(response['Body'].read())
        results.append(result)
    
    # Aggregate and save to S3
    s3 = boto3.client('s3')
    output_key = event['original_key'].replace('uploads/', 'results/') + '.json'
    s3.put_object(
        Bucket=event['bucket'],
        Key=output_key,
        Body=json.dumps(results)
    )
    
    return {{'results_key': output_key, 'findings_count': len(results)}}
"""),
            timeout=Duration.minutes(5),
            memory_size=1024,
            environment={"ENDPOINT_NAME": endpoint.endpoint_name}
        )
        
        CfnOutput(self, "EndpointName", value=endpoint.endpoint_name)
        CfnOutput(self, "BucketName", value=bucket.bucket_name)
        CfnOutput(self, "ParserLambda", value=parser_fn.function_name)
        CfnOutput(self, "InvokerLambda", value=invoker_fn.function_name)
        CfnOutput(self, "MonthlyCost", value="~$200-400 (serverless SageMaker)")

app = cdk.App()
LLMSecurityScannerStack(app, "LLMSecurityScannerStack",
    env=cdk.Environment(account=app.account, region=app.region or "us-east-1")
)
app.synth()