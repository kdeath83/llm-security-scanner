#!/usr/bin/env python3
"""
LLM Security Scanner - AWS CDK Stack
One-click deployment for cost-optimized code security assessment
using self-hosted Llama 3.1 on SageMaker
"""
import aws_cdk as cdk
from constructs import Construct
from aws_cdk import (
    Stack, RemovalPolicy, Duration, Size,
    aws_sagemaker as sagemaker,
    aws_lambda as lambda_,
    aws_opensearchserverless as opensearch,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
    aws_s3 as s3,
    aws_iam as iam,
    aws_ec2 as ec2,
    CfnOutput, Fn
)

class LLMSecurityScannerStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Configuration
        self.model_id = "meta-textgeneration-llama-3-1-8b-instruct"
        self.instance_type = "ml.g5.xlarge"  # ~$1.50/hr, cheapest GPU
        
        # VPC for SageMaker
        vpc = ec2.Vpc(self, "ScannerVPC",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                )
            ]
        )
        
        # Security Group for SageMaker
        sg = ec2.SecurityGroup(self, "SageMakerSG",
            vpc=vpc,
            description="Security group for LLM Security Scanner",
            allow_all_outbound=True
        )
        
        # S3 Bucket for code uploads and results
        bucket = s3.Bucket(self, "ScannerBucket",
            bucket_name=f"llm-security-scanner-{self.account}",
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.RETAIN,
            cors=[
                s3.CorsRule(
                    allowed_methods=[s3.HttpMethods.GET, s3.HttpMethods.POST],
                    allowed_origins=["*"],
                    allowed_headers=["*"]
                )
            ]
        )
        
        # OpenSearch Serverless for vector store (RAG)
        collection_name = "security-patterns"
        
        # IAM role for SageMaker
        sagemaker_role = iam.Role(self, "SageMakerRole",
            assumed_by=iam.ServicePrincipal("sagemaker.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerFullAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3ReadOnlyAccess")
            ]
        )
        bucket.grant_read_write(sagemaker_role)
        
        # SageMaker Endpoint (Llama 3.1 8B)
        # Using JumpStart model
        model = sagemaker.CfnModel(self, "LlamaModel",
            model_name="llama-3-1-8b-security",
            execution_role_arn=sagemaker_role.role_arn,
            primary_container=sagemaker.CfnModel.ContainerDefinitionProperty(
                image=sagemaker.CfnModel.ImageConfigProperty(
                    repository_access_mode="Platform"
                ),
                model_data_url=f"s3://jumpstart-cache-prod-{self.region}/meta-textgeneration/meta-textgeneration-llama-3-1-8b-instruct/artifacts/inference-prepack/v1.0.0/",  # JumpStart cache
                environment={
                    "SAGEMAKER_PROGRAM": "inference.py",
                    "SAGEMAKER_SUBMIT_DIRECTORY": "/opt/ml/model/code"
                }
            )
        )
        
        # For actual deployment, use JumpStart programmatic approach
        # This creates the endpoint configuration
        endpoint_config = sagemaker.CfnEndpointConfig(self, "EndpointConfig",
            endpoint_config_name="llama-8b-config",
            production_variants=[
                sagemaker.CfnEndpointConfig.ProductionVariantProperty(
                    variant_name="AllTraffic",
                    model_name=model.model_name,
                    initial_instance_count=1,
                    instance_type=self.instance_type,
                    initial_variant_weight=1.0,
                    serverless_config=sagemaker.CfnEndpointConfig.ServerlessConfigProperty(
                        max_concurrency=50,
                        memory_size_in_mb=4096
                    )
                )
            ]
        )
        
        endpoint = sagemaker.CfnEndpoint(self, "LlamaEndpoint",
            endpoint_name="llama-security-scanner",
            endpoint_config_name=endpoint_config.endpoint_config_name
        )
        
        endpoint.add_dependency(endpoint_config)
        endpoint_config.add_dependency(model)
        
        # Lambda function for code parsing and chunking
        parser_role = iam.Role(self, "ParserRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )
        bucket.grant_read_write(parser_role)
        
        parser_lambda = lambda_.Function(self, "CodeParser",
            function_name="llm-security-parser",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="parser.handler",
            code=lambda_.Code.from_asset("../../src/parser"),
            timeout=Duration.minutes(5),
            memory_size=2048,
            environment={
                "BUCKET_NAME": bucket.bucket_name,
                "ENDPOINT_NAME": endpoint.endpoint_name
            },
            role=parser_role
        )
        
        # Lambda for LLM invocation
        invoker_role = iam.Role(self, "InvokerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ]
        )
        invoker_role.add_to_policy(iam.PolicyStatement(
            actions=["sagemaker:InvokeEndpoint"],
            resources=[f"arn:aws:sagemaker:{self.region}:{self.account}:endpoint/{endpoint.endpoint_name}"]
        ))
        bucket.grant_read_write(invoker_role)
        
        invoker_lambda = lambda_.Function(self, "LLMInvoker",
            function_name="llm-security-invoker",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="invoker.handler",
            code=lambda_.Code.from_asset("../../src/invoker"),
            timeout=Duration.minutes(2),
            memory_size=1024,
            environment={
                "ENDPOINT_NAME": endpoint.endpoint_name,
                "REGION": self.region
            },
            role=invoker_role
        )
        
        # Step Functions State Machine
        definition = sfn.Chain\
            .start(sfn_tasks.LambdaInvoke(self, "ParseCode",
                lambda_function=parser_lambda,
                output_path="$.Payload"
            ))\
            .next(sfn_tasks.LambdaInvoke(self, "AnalyzeWithLLM",
                lambda_function=invoker_lambda,
                output_path="$.Payload"
            ))\
            .next(sfn.Succeed(self, "AnalysisComplete"))
        
        state_machine = sfn.StateMachine(self, "SecurityScannerWorkflow",
            state_machine_name="llm-security-scanner",
            definition=definition,
            timeout=Duration.minutes(10)
        )
        
        # API Gateway or trigger could be added here
        
        # Outputs
        CfnOutput(self, "SageMakerEndpoint",
            value=endpoint.endpoint_name,
            description="SageMaker endpoint for LLM inference"
        )
        CfnOutput(self, "S3Bucket",
            value=bucket.bucket_name,
            description="S3 bucket for code and results"
        )
        CfnOutput(self, "StepFunctionArn",
            value=state_machine.state_machine_arn,
            description="Step Functions workflow ARN"
        )
        CfnOutput(self, "EstimatedMonthlyCost",
            value="~$400-600 (g5.xlarge 24/7 + storage)",
            description="Estimated cost with always-on endpoint"
        )

app = cdk.App()
LLMSecurityScannerStack(app, "LLMSecurityScannerStack",
    env=cdk.Environment(
        account=app.account,
        region=app.region or "us-east-1"
    )
)
app.synth()