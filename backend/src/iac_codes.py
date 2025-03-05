import os
import json
import boto3
import logging
import uuid
from datetime import datetime
from auth import verify_google_token

# 设置日志
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# DynamoDB
dynamodb = boto3.resource('dynamodb')
codes_table = dynamodb.Table(os.environ.get('CODES_TABLE', 'iacCodes'))

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

def create_iac_code(user_id, code_data):
    """创建新的IAC代码"""
    try:
        code_id = str(uuid.uuid4())
        
        code_item = {
            'id': code_id,
            'user_id': user_id,
            'name': code_data['name'],
            'code': code_data['code'],
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        codes_table.put_item(Item=code_item)
        
        return {
            'id': code_id,
            'name': code_data['name'],
            'created_at': code_item['created_at']
        }
    except Exception as e:
        logger.error(f"创建IAC代码错误: {str(e)}")
        raise

def get_iac_codes(user_id):
    """获取用户的IAC代码"""
    try:
        response = codes_table.query(
            IndexName='UserIdIndex',
            KeyConditionExpression=boto3.dynamodb.conditions.Key('user_id').eq(user_id)
        )
        
        codes = []
        for item in response.get('Items', []):
            codes.append({
                'id': item['id'],
                'name': item['name'],
                'created_at': item['created_at']
            })
        
        return codes
    except Exception as e:
        logger.error(f"获取IAC代码错误: {str(e)}")
        raise

def get_iac_code(code_id, user_id):
    """获取特定的IAC代码"""
    try:
        response = codes_table.get_item(Key={'id': code_id})
        
        if 'Item' not in response:
            return None
        
        code = response['Item']
        
        # 验证用户是否有权限访问此代码
        if code['user_id'] != user_id:
            return None
        
        return {
            'id': code['id'],
            'name': code['name'],
            'code': code['code'],
            'created_at': code['created_at']
        }
    except Exception as e:
        logger.error(f"获取IAC代码错误: {str(e)}")
        raise

def delete_iac_code(code_id, user_id):
    """删除IAC代码"""
    try:
        # 先检查代码是否存在且属于该用户
        response = codes_table.get_item(Key={'id': code_id})
        
        if 'Item' not in response:
            return False
        
        code = response['Item']
        
        if code['user_id'] != user_id:
            return False
        
        # 删除代码
        codes_table.delete_item(Key={'id': code_id})
        
        return True
    except Exception as e:
        logger.error(f"删除IAC代码错误: {str(e)}")
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
        
        # 获取HTTP方法
        http_method = event['httpMethod']
        
        # 创建代码
        if http_method == 'POST':
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
            
            # 验证请求
            required_fields = ['name', 'code']
            for field in required_fields:
                if field not in body:
                    return {
                        'statusCode': 400,
                        'body': json.dumps({'message': f'缺少必要字段: {field}'})
                    }
            
            code = create_iac_code(user_id, body)
            
            return {
                'statusCode': 201,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': True
                },
                'body': json.dumps(code)
            }
        
        # 获取所有代码
        elif http_method == 'GET' and ('pathParameters' not in event or not event['pathParameters']):
            codes = get_iac_codes(user_id)
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': True
                },
                'body': json.dumps(codes)
            }
        
        # 获取特定代码
        elif http_method == 'GET' and 'pathParameters' in event and event['pathParameters']:
            code_id = event['pathParameters']['codeId']
            code = get_iac_code(code_id, user_id)
            
            if not code:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'message': '未找到代码或无权访问'})
                }
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': True
                },
                'body': json.dumps(code)
            }
        
        # 删除代码
        elif http_method == 'DELETE':
            code_id = event['pathParameters']['codeId']
            success = delete_iac_code(code_id, user_id)
            
            if not success:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'message': '未找到代码或无权删除'})
                }
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': True
                },
                'body': json.dumps({'message': '删除成功'})
            }
        
        else:
            return {
                'statusCode': 405,
                'body': json.dumps({'message': '不支持的方法'})
            }
    
    except Exception as e:
        logger.error(f"处理IAC代码请求错误: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'服务器错误: {str(e)}'})
        } 