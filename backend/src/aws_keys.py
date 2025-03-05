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
keys_table = dynamodb.Table(os.environ.get('KEYS_TABLE', 'iacAwsKeys'))

# KMS for encryption
kms = boto3.client('kms')
KMS_KEY_ID = os.environ.get('KMS_KEY_ID', '')

def encrypt_secret(secret):
    """使用KMS加密敏感数据"""
    try:
        response = kms.encrypt(
            KeyId=KMS_KEY_ID,
            Plaintext=secret.encode('utf-8')
        )
        return response['CiphertextBlob']
    except Exception as e:
        logger.error(f"加密错误: {str(e)}")
        raise

def decrypt_secret(encrypted_secret):
    """使用KMS解密敏感数据"""
    try:
        response = kms.decrypt(
            CiphertextBlob=encrypted_secret
        )
        return response['Plaintext'].decode('utf-8')
    except Exception as e:
        logger.error(f"解密错误: {str(e)}")
        raise

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

def create_aws_key(user_id, key_data):
    """创建新的AWS密钥"""
    try:
        key_id = str(uuid.uuid4())
        
        # 加密Secret Access Key
        encrypted_secret_key = encrypt_secret(key_data['secretKey'])
        
        key_item = {
            'id': key_id,
            'user_id': user_id,
            'name': key_data['name'],
            'access_key': key_data['accessKey'],
            'secret_key': encrypted_secret_key,
            'region': key_data['region'],
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        keys_table.put_item(Item=key_item)
        
        # 返回不包含敏感信息的数据
        return {
            'id': key_id,
            'name': key_data['name'],
            'access_key': key_data['accessKey'],
            'region': key_data['region'],
            'created_at': key_item['created_at']
        }
    except Exception as e:
        logger.error(f"创建AWS密钥错误: {str(e)}")
        raise

def get_aws_keys(user_id):
    """获取用户的AWS密钥"""
    try:
        response = keys_table.query(
            IndexName='UserIdIndex',
            KeyConditionExpression=boto3.dynamodb.conditions.Key('user_id').eq(user_id)
        )
        
        keys = []
        for item in response.get('Items', []):
            # 返回不包含敏感信息的数据
            keys.append({
                'id': item['id'],
                'name': item['name'],
                'access_key': item['access_key'],
                'region': item['region'],
                'created_at': item['created_at']
            })
        
        return keys
    except Exception as e:
        logger.error(f"获取AWS密钥错误: {str(e)}")
        raise

def get_aws_key(key_id, user_id):
    """获取特定的AWS密钥"""
    try:
        response = keys_table.get_item(Key={'id': key_id})
        
        if 'Item' not in response:
            return None
        
        key = response['Item']
        
        # 验证用户是否有权限访问此密钥
        if key['user_id'] != user_id:
            return None
        
        # 解密Secret Access Key
        decrypted_secret_key = decrypt_secret(key['secret_key'])
        
        return {
            'id': key['id'],
            'name': key['name'],
            'access_key': key['access_key'],
            'secret_key': decrypted_secret_key,
            'region': key['region'],
            'created_at': key['created_at']
        }
    except Exception as e:
        logger.error(f"获取AWS密钥错误: {str(e)}")
        raise

def delete_aws_key(key_id, user_id):
    """删除AWS密钥"""
    try:
        # 先检查密钥是否存在且属于该用户
        response = keys_table.get_item(Key={'id': key_id})
        
        if 'Item' not in response:
            return False
        
        key = response['Item']
        
        if key['user_id'] != user_id:
            return False
        
        # 删除密钥
        keys_table.delete_item(Key={'id': key_id})
        
        return True
    except Exception as e:
        logger.error(f"删除AWS密钥错误: {str(e)}")
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
        
        # 创建密钥
        if http_method == 'POST':
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
            
            # 验证请求
            required_fields = ['name', 'accessKey', 'secretKey', 'region']
            for field in required_fields:
                if field not in body:
                    return {
                        'statusCode': 400,
                        'body': json.dumps({'message': f'缺少必要字段: {field}'})
                    }
            
            key = create_aws_key(user_id, body)
            
            return {
                'statusCode': 201,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': True
                },
                'body': json.dumps(key)
            }
        
        # 获取所有密钥
        elif http_method == 'GET' and 'pathParameters' not in event or not event['pathParameters']:
            keys = get_aws_keys(user_id)
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': True
                },
                'body': json.dumps(keys)
            }
        
        # 获取特定密钥
        elif http_method == 'GET' and 'pathParameters' in event and event['pathParameters']:
            key_id = event['pathParameters']['keyId']
            key = get_aws_key(key_id, user_id)
            
            if not key:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'message': '未找到密钥或无权访问'})
                }
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': True
                },
                'body': json.dumps(key)
            }
        
        # 删除密钥
        elif http_method == 'DELETE':
            key_id = event['pathParameters']['keyId']
            success = delete_aws_key(key_id, user_id)
            
            if not success:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'message': '未找到密钥或无权删除'})
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
        logger.error(f"处理AWS密钥请求错误: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'服务器错误: {str(e)}'})
        } 