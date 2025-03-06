const API_BASE_URL = 'https://api.getmemap.com';
// Google认证状态日志记录函数
function logAuthStatus(message, type = 'info') {
    // 使用新的调试日志系统
    window.DebugLogger.log(message, window.DebugLogger.LOG_TYPE.AUTH);
}

// Google One Tap登录回调（新版API）
function onGoogleSignIn(response) {
    try {
        logAuthStatus('Google登录成功，正在获取用户信息...');
        
        // 从credential中解析JWT
        const jwt = parseJwt(response.credential);
        
        // 记录用户信息
        logAuthStatus(`用户ID: ${jwt.sub}`);
        logAuthStatus(`用户名: ${jwt.name}`);
        logAuthStatus(`邮箱: ${jwt.email}`);
        
        // 存储用户信息到本地存储
        localStorage.setItem('user_id', jwt.sub);
        localStorage.setItem('user_name', jwt.name);
        localStorage.setItem('user_email', jwt.email);
        localStorage.setItem('id_token', response.credential);
        
        logAuthStatus('正在向后端服务验证身份...');
        
        // 记录API请求开始
        window.DebugLogger.log('发送身份验证请求', window.DebugLogger.LOG_TYPE.API, {
            endpoint: '/auth/verify',
            method: 'POST',
            data: { id_token: '***' } // 不显示实际令牌
        });
        
        // 向后端API发送验证请求
        fetch(`${API_BASE_URL}/auth/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id_token: response.credential })
        })
        .then(response => {
            // 记录API响应
            window.DebugLogger.log(`收到身份验证响应: ${response.status}`, 
                window.DebugLogger.LOG_TYPE.API, { status: response.status });
            
            if (!response.ok) {
                throw new Error('后端验证失败');
            }
            return response.json();
        })
        .then(data => {
            // 记录验证成功
            window.DebugLogger.log('身份验证成功', window.DebugLogger.LOG_TYPE.AUTH, {
                user_id: data.user_id,
                success: true
            });
            
            logAuthStatus('身份验证成功，正在加载用户数据...');
            
            // 显示登出按钮
            document.getElementById('signout-button').style.display = 'block';
            // 显示主内容
            document.getElementById('main-content').style.display = 'block';
            
            // 记录Lambda函数调用
            window.DebugLogger.log('触发Lambda函数: 用户验证', window.DebugLogger.LOG_TYPE.LAMBDA);
            
            // 记录数据库操作
            window.DebugLogger.log('DynamoDB操作: 获取/创建用户记录', window.DebugLogger.LOG_TYPE.DB);
            
            // 触发加载用户数据
            if (typeof loadUserData === 'function') {
                loadUserData();
            }
        })
        .catch(error => {
            // 记录错误
            window.DebugLogger.log(`验证失败: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
                error: error.message,
                stack: error.stack
            });
            
            logAuthStatus(`验证失败: ${error.message}`);
            signOut();
        });
    } catch (error) {
        // 记录错误
        window.DebugLogger.log(`登录过程发生错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
        
        logAuthStatus(`登录过程发生错误: ${error.message}`);
    }
}

// 解析JWT
function parseJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (error) {
        window.DebugLogger.log(`JWT解析失败: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR);
        return {};
    }
}

// 兼容旧版API的onSignIn函数
function onSignIn(googleUser) {
    try {
        logAuthStatus('检测到旧版API调用，重定向到新版处理函数');
        // 获取ID令牌
        const id_token = googleUser.getAuthResponse().id_token;
        // 调用新版处理函数
        onGoogleSignIn({ credential: id_token });
    } catch (error) {
        window.DebugLogger.log(`旧版登录处理失败: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
    }
}

// 退出登录
function signOut() {
    try {
        logAuthStatus('正在退出登录...');
        
        // 使用新的Google Identity Services API退出
        google.accounts.id.disableAutoSelect();
        
        // 清除本地存储
        localStorage.removeItem('user_id');
        localStorage.removeItem('user_name');
        localStorage.removeItem('user_email');
        localStorage.removeItem('id_token');
        
        // 隐藏登出按钮
        document.getElementById('signout-button').style.display = 'none';
        // 隐藏主内容
        document.getElementById('main-content').style.display = 'none';
        
        // 记录退出状态
        window.DebugLogger.log('用户已退出登录', window.DebugLogger.LOG_TYPE.AUTH);
        
        logAuthStatus('退出登录成功');
    } catch (error) {
        window.DebugLogger.log(`退出过程发生错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
    }
}

// 初始化Google API客户端
function initGoogleAuth() {
    try {
        logAuthStatus('初始化Google认证...');
        window.DebugLogger.log('开始初始化Google认证', window.DebugLogger.LOG_TYPE.AUTH);
        
        // 检查是否已经登录
        if (localStorage.getItem('id_token')) {
            const tokenData = parseJwt(localStorage.getItem('id_token'));
            const now = Date.now() / 1000;
            
            // 检查令牌是否有效（未过期）
            if (tokenData && tokenData.exp && tokenData.exp > now) {
                window.DebugLogger.log('检测到有效的登录令牌', window.DebugLogger.LOG_TYPE.AUTH);
                
                // 显示主内容
                document.getElementById('signout-button').style.display = 'block';
                document.getElementById('main-content').style.display = 'block';
                
                // 加载用户数据
                if (typeof loadUserData === 'function') {
                    loadUserData();
                }
            } else {
                // 令牌已过期，清除
                localStorage.removeItem('id_token');
                window.DebugLogger.log('令牌已过期，需要重新登录', window.DebugLogger.LOG_TYPE.AUTH);
            }
        }
    } catch (error) {
        window.DebugLogger.log(`认证初始化错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    try {
        // 初始化调试日志系统
        if (window.DebugLogger) {
            window.DebugLogger.log('页面已加载，正在初始化认证系统', window.DebugLogger.LOG_TYPE.AUTH);
        }
        
        // 初始化认证
        initGoogleAuth();
    } catch (error) {
        console.error('页面加载初始化失败:', error);
        if (window.DebugLogger) {
            window.DebugLogger.log(`页面加载初始化失败: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
                error: error.message,
                stack: error.stack
            });
        }
    }
}); 