# AWS IAC代码执行平台

这是一个使用 AWS 基础设施作为代码 (Infrastructure as Code) 执行平台，允许用户通过 Google 账号登录，管理 AWS 凭证和 IAC 代码，并在 AWS 上执行这些代码。

## 功能特点

- Google 账号认证和授权
- 安全存储和管理 AWS 账户密钥
- 创建和管理 IAC 代码 (支持 Terraform 和 CloudFormation)
- 执行 IAC 代码并查看结果
- 美观的用户界面和实时认证状态跟踪

## 技术栈

### 前端
- HTML5 + CSS3 + JavaScript
- 响应式设计
- Google 认证 API

### 后端
- AWS Lambda
- Amazon API Gateway
- Amazon DynamoDB
- AWS KMS (用于加密 AWS 凭证)
- Amazon Cognito (用户池和身份验证)

### 基础设施
- Amazon S3 (静态网站托管)
- Amazon CloudFront (CDN)
- AWS IAM (身份和访问管理)
- GitHub Actions (CI/CD)

## 安装与部署

### 前置条件
- AWS 账户
- Google 开发者账户 (用于 OAuth 配置)
- GitHub 账户 (用于 CI/CD)

### 部署步骤

1. **设置 Google OAuth 凭证**
   - 在 [Google Cloud Console](https://console.cloud.google.com/) 创建一个项目
   - 设置 OAuth 同意屏幕和凭证
   - 获取客户端 ID 和密钥

2. **设置 AWS 资源**
   - 创建 S3 桶用于静态文件托管
   - 部署 API Gateway 和 Lambda 函数
   - 设置 DynamoDB 表和 KMS 密钥
   - 设置 CloudFront 分配

3. **设置 GitHub Actions**
   - 在 GitHub 存储库设置中添加以下 Secrets:
     - `AWS_REGION`
     - `AWS_ACCESS_KEY_ID`
     - `AWS_SECRET_ACCESS_KEY`
     - `AWS_ROLE_ARN`
     - `AWS_S3_BUCKET`
     - `DOMAIN_NAME`

## 使用指南

1. 通过 Google 账号登录系统
2. 添加您的 AWS 账户凭证
3. 创建新的 IAC 代码或选择已保存的代码
4. 选择 AWS 凭证并执行代码
5. 查看执行结果

## 本地开发

1. 克隆此仓库
```
git clone https://github.com/yourusername/aws-iac-platform.git
cd aws-iac-platform
```

2. 更新 API 端点
在 `static/js/app.js` 中更新 `API_BASE_URL` 为您的 API Gateway 端点

3. 在本地测试前端
```
# 使用 Python 的内置 HTTP 服务器
python3 -m http.server 8000
```

## 安全注意事项

- AWS 密钥使用 KMS 加密存储在 DynamoDB 中
- 每个用户只能访问自己的密钥和代码
- API 请求通过 AWS Cognito 进行授权
- 仅通过 HTTPS 提供服务
- 确保 IAC 代码执行 Lambda 函数具有最小权限

## 贡献者

- [您的名字]

## 许可证

[MIT](LICENSE) 