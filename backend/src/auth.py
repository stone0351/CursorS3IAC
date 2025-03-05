import os
import json
import boto3
import logging
import google.auth.transport.requests
from google.oauth2 import id_token
import uuid
from datetime import datetime, timedelta

# 设置日志
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Google Client ID
GOOGLE_CLIENT_ID = '368121835122-4tpffhrba2q7kd1hicnbm4cnpg01a4ac.apps.googleusercontent.com'

# DynamoDB
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table(os.environ.get('USERS_TABLE', 'iacUsers'))

def verify_google_token(token):
    """验证Google Token的有效性"""
    try:
        request = google.auth.transport.requests.Request()
        id_info = id_token.verify_oauth2_token(token, request, GOOGLE_CLIENT_ID)
        
        # 检查令牌是否过期
        if id_info['exp'] < datetime.now().timestamp():
            return None
        
        # 检查令牌的颁发者
        if id_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            return None
        
        # 检查令牌的受众
        if id_info['aud'] != GOOGLE_CLIENT_ID:
            return None
        
        return id_info
    except Exception as e:
        logger.error(f"Token验证错误: {str(e)}")
        return None

def get_or_create_user(user_info):
    """获取或创建用户记录"""
    try:
        user_id = user_info['sub']
        email = user_info['email']
        name = user_info.get('name', '')
        
        # 尝试获取现有用户
        response = users_table.get_item(Key={'user_id': user_id})
        
        if 'Item' in response:
            # 更新用户的最后登录时间
            users_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression='SET last_login = :last_login',
                ExpressionAttributeValues={':last_login': datetime.now().isoformat()}
            )
            return response['Item']
        else:
            # 创建新用户
            new_user = {
                'user_id': user_id,
                'email': email,
                'name': name,
                'created_at': datetime.now().isoformat(),
                'last_login': datetime.now().isoformat()
            }
            users_table.put_item(Item=new_user)
            return new_user
    except Exception as e:
        logger.error(f"获取或创建用户错误: {str(e)}")
        raise

def handler(event, context):
    """Lambda处理函数"""
    try:
        # 解析请求
        if 'body' not in event:
            return {
                'statusCode': 400,
                'body': json.dumps({'message': '无效的请求'})
            }
        
        body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        
        if 'id_token' not in body:
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Missing id_token'})
            }
        
        # 验证Token
        id_token = body['id_token']
        user_info = verify_google_token(id_token)
        
        if not user_info:
            return {
                'statusCode': 401,
                'body': json.dumps({'message': '无效的令牌'})
            }
        
        # 获取或创建用户
        user = get_or_create_user(user_info)
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': True
            },
            'body': json.dumps({
                'user_id': user['user_id'],
                'email': user['email'],
                'name': user.get('name', ''),
                'message': '认证成功'
            })
        }
    except Exception as e:
        logger.error(f"认证处理错误: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'message': f'服务器错误: {str(e)}'})
        } 