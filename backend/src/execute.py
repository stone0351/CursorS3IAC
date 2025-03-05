import os
import json
import boto3
import logging
import tempfile
import subprocess
import uuid
import base64
from datetime import datetime
from auth import verify_google_token
from aws_keys import get_aws_key
from iac_codes import get_iac_code

# 设置日志
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# DynamoDB
dynamodb = boto3.resource('dynamodb')
executions_table = dynamodb.Table(os.environ.get('EXECUTIONS_TABLE', 'iacExecutions'))

def get_user_id_from_token(event):
    """从请求中获取用户ID"""
    try:
        # 从请求头中获取Authorization
        headers = event.get('headers', {})
        auth_header = headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header[7:]  # 去掉前缀 "Bearer "
        user_info = verify_google_token(token)
        
        if not user_info:
            return None
        
        return user_info['sub']
    except Exception as e:
        logger.error(f"获取用户ID错误: {str(e)}")
        return None

def execute_terraform(code, aws_access_key, aws_secret_key, aws_region):
    """执行Terraform代码"""
    try:
        # 创建临时目录
        with tempfile.TemporaryDirectory() as tmpdirname:
            # 创建Terraform配置文件
            tf_file_path = os.path.join(tmpdirname, 'main.tf')
            with open(tf_file_path, 'w') as f:
                f.write(code)
            
            # 设置环境变量
            env = os.environ.copy()
            env['AWS_ACCESS_KEY_ID'] = aws_access_key
            env['AWS_SECRET_ACCESS_KEY'] = aws_secret_key
            env['AWS_REGION'] = aws_region
            
            # 执行Terraform初始化
            init_process = subprocess.Popen(
                ['terraform', 'init'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tmpdirname,
                env=env
            )
            init_stdout, init_stderr = init_process.communicate()
            
            if init_process.returncode != 0:
                return {
                    'success': False,
                    'output': f"初始化失败:\n{init_stderr.decode('utf-8')}"
                }
            
            # 执行Terraform计划
            plan_process = subprocess.Popen(
                ['terraform', 'plan', '-out=tfplan'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tmpdirname,
                env=env
            )
            plan_stdout, plan_stderr = plan_process.communicate()
            
            if plan_process.returncode != 0:
                return {
                    'success': False,
                    'output': f"计划失败:\n{plan_stderr.decode('utf-8')}"
                }
            
            # 执行Terraform应用
            apply_process = subprocess.Popen(
                ['terraform', 'apply', '-auto-approve', 'tfplan'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tmpdirname,
                env=env
            )
            apply_stdout, apply_stderr = apply_process.communicate()
            
            if apply_process.returncode != 0:
                return {
                    'success': False,
                    'output': f"应用失败:\n{apply_stderr.decode('utf-8')}"
                }
            
            # 执行Terraform输出
            output_process = subprocess.Popen(
                ['terraform', 'output', '-json'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tmpdirname,
                env=env
            )
            output_stdout, output_stderr = output_process.communicate()
            
            combined_output = (
                f"初始化输出:\n{init_stdout.decode('utf-8')}\n\n"
                f"计划输出:\n{plan_stdout.decode('utf-8')}\n\n"
                f"应用输出:\n{apply_stdout.decode('utf-8')}\n\n"
                f"输出结果:\n{output_stdout.decode('utf-8')}"
            )
            
            return {
                'success': True,
                'output': combined_output
            }
    except Exception as e:
        logger.error(f"执行Terraform错误: {str(e)}")
        return {
            'success': False,
            'output': f"执行错误: {str(e)}"
        }

def execute_cloudformation(code, aws_access_key, aws_secret_key, aws_region):
    """执行CloudFormation代码"""
    try:
        # 创建临时目录
        with tempfile.TemporaryDirectory() as tmpdirname:
            # 创建CloudFormation模板文件
            template_path = os.path.join(tmpdirname, 'template.yaml')
            with open(template_path, 'w') as f:
                f.write(code)
            
            # 配置AWS凭证
            session = boto3.Session(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )
            
            # 创建CloudFormation客户端
            cf_client = session.client('cloudformation')
            
            # 生成唯一的堆栈名称
            stack_name = f"iac-execution-{uuid.uuid4().hex[:8]}"
            
            # 读取模板文件
            with open(template_path, 'r') as f:
                template_body = f.read()
            
            # 创建CloudFormation堆栈
            response = cf_client.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND'],
                OnFailure='DELETE'
            )
            
            # 等待堆栈创建完成
            waiter = cf_client.get_waiter('stack_create_complete')
            try:
                waiter.wait(StackName=stack_name)
                
                # 获取堆栈输出
                stack_response = cf_client.describe_stacks(StackName=stack_name)
                outputs = stack_response['Stacks'][0].get('Outputs', [])
                
                output_str = "堆栈创建成功!\n\n"
                if outputs:
                    output_str += "输出:\n"
                    for output in outputs:
                        output_str += f"{output['OutputKey']}: {output['OutputValue']}\n"
                
                return {
                    'success': True,
                    'output': output_str
                }
            except Exception as e:
                # 获取堆栈错误
                try:
                    stack_events = cf_client.describe_stack_events(StackName=stack_name)
                    error_events = [
                        event for event in stack_events['StackEvents']
                        if 'ResourceStatus' in event and event['ResourceStatus'].endswith('_FAILED')
                    ]
                    
                    error_str = "堆栈创建失败!\n\n错误:\n"
                    for event in error_events:
                        error_str += f"{event['LogicalResourceId']}: {event['ResourceStatusReason']}\n"
                    
                    return {
                        'success': False,
                        'output': error_str
                    }
                except Exception:
                    return {
                        'success': False,
                        'output': f"堆栈创建失败: {str(e)}"
                    }
    except Exception as e:
        logger.error(f"执行CloudFormation错误: {str(e)}")
        return {
            'success': False,
            'output': f"执行错误: {str(e)}"
        }

def save_execution(user_id, key_id, code_id, success, output):
    """保存执行记录"""
    try:
        execution_id = str(uuid.uuid4())
        
        execution_item = {
            'id': execution_id,
            'user_id': user_id,
            'key_id': key_id,
            'code_id': code_id,
            'success': success,
            'output': base64.b64encode(output.encode('utf-8')).decode('utf-8'),  # 编码输出以避免DynamoDB大小限制
            'executed_at': datetime.now().isoformat()
        }
        
        executions_table.put_item(Item=execution_item)
        
        return execution_id
    except Exception as e:
        logger.error(f"保存执行记录错误: {str(e)}")
        raise

def handler(event, context):
    """Lambda处理函数"""
    try:
        # 获取用户ID
        user_id = get_user_id_from_token(event)
        
        if not user_id:
            return {
                'statusCode': 401,
                'body': json.dumps({'message': '未授权'})
            }
        
        # 解析请求
        if 'body' not in event:
            return {
                'statusCode': 400,
                'body': json.dumps({'message': '无效的请求'})
            }
        
        body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        
        # 验证请求
        required_fields = ['keyId', 'codeId']
        for field in required_fields:
            if field not in body:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'message': f'缺少必要字段: {field}'})
                }
        
        key_id = body['keyId']
        code_id = body['codeId']
        
        # 获取AWS密钥
        key = get_aws_key(key_id, user_id)
        if not key:
            return {
                'statusCode': 404,
                'body': json.dumps({'message': '未找到AWS密钥或无权访问'})
            }
        
        # 获取IAC代码
        code = get_iac_code(code_id, user_id)
        if not code:
            return {
                'statusCode': 404,
                'body': json.dumps({'message': '未找到IAC代码或无权访问'})
            }
        
        # 判断代码类型并执行
        code_content = code['code']
        
        # 简单的判断代码类型
        if 'provider "aws"' in code_content:
            # Terraform代码
            result = execute_terraform(
                code_content,
                key['access_key'],
                key['secret_key'],
                key['region']
            )
        else:
            # 默认为CloudFormation
            result = execute_cloudformation(
                code_content,
                key['access_key'],
                key['secret_key'],
                key['region']
            )
        
        # 保存执行记录
        execution_id = save_execution(
            user_id,
            key_id,
            code_id,
            result['success'],
            result['output']
        )
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': True
            },
            'body': json.dumps({
                'execution_id': execution_id,
                'success': result['success'],
                'output': result['output']
            })
        }
    
    except Exception as e:
        logger.error(f"执行IAC代码错误: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'服务器错误: {str(e)}'})
        } 