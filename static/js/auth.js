// Google认证状态日志记录函数
function logAuthStatus(message, type = 'info') {
    // 使用新的调试日志系统
    window.DebugLogger.log(message, window.DebugLogger.LOG_TYPE.AUTH);
}

// 用户成功登录后的回调
function onSignIn(googleUser) {
    try {
        logAuthStatus('Google登录成功，正在获取用户信息...');
        
        // 获取用户基本信息
        const profile = googleUser.getBasicProfile();
        const id_token = googleUser.getAuthResponse().id_token;
        
        // 记录用户信息
        logAuthStatus(`用户ID: ${profile.getId()}`);
        logAuthStatus(`用户名: ${profile.getName()}`);
        logAuthStatus(`邮箱: ${profile.getEmail()}`);
        
        // 存储用户信息到本地存储
        localStorage.setItem('user_id', profile.getId());
        localStorage.setItem('user_name', profile.getName());
        localStorage.setItem('user_email', profile.getEmail());
        localStorage.setItem('id_token', id_token);
        
        logAuthStatus('正在向后端服务验证身份...');
        
        // 记录API请求开始
        window.DebugLogger.log('发送身份验证请求', window.DebugLogger.LOG_TYPE.API, {
            endpoint: '/auth/verify',
            method: 'POST',
            data: { id_token: '***' } // 不显示实际令牌
        });
        
        // 向后端API发送验证请求
        fetch('https://api.example.com/auth/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id_token })
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

// 退出登录
function signOut() {
    try {
        const auth2 = gapi.auth2.getAuthInstance();
        
        logAuthStatus('正在退出登录...');
        
        auth2.signOut().then(() => {
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
        }).catch(error => {
            // 记录退出错误
            window.DebugLogger.log(`退出登录失败: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
                error: error.message
            });
            
            logAuthStatus(`退出登录失败: ${error.message}`);
        });
    } catch (error) {
        window.DebugLogger.log(`退出过程发生错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
    }
}

// 初始化Google API客户端 - 修改为使用getAuthInstance
function initGoogleAuth() {
    logAuthStatus('初始化Google认证...');
    window.DebugLogger.log('开始初始化Google认证', window.DebugLogger.LOG_TYPE.AUTH);
    
    // 检查gapi是否已加载
    if (typeof gapi === 'undefined') {
        window.DebugLogger.log('Google API尚未加载', window.DebugLogger.LOG_TYPE.ERROR);
        logAuthStatus('Google API尚未加载，请稍后再试');
        return;
    }
    
    gapi.load('auth2', () => {
        window.DebugLogger.log('Google auth2 API已加载', window.DebugLogger.LOG_TYPE.AUTH);
        
        // 检查auth2是否已初始化
        if (gapi.auth2.getAuthInstance()) {
            window.DebugLogger.log('检测到Google Auth已初始化，使用现有实例', window.DebugLogger.LOG_TYPE.AUTH);
            logAuthStatus('Google认证已初始化');
            
            // 检查用户是否已经登录
            const auth2 = gapi.auth2.getAuthInstance();
            if (auth2.isSignedIn.get()) {
                window.DebugLogger.log('检测到现有登录，正在自动登录...', window.DebugLogger.LOG_TYPE.AUTH);
                logAuthStatus('检测到现有登录，正在自动登录...');
                const googleUser = auth2.currentUser.get();
                onSignIn(googleUser);
            }
            return;
        }
        
        // 只有在未初始化的情况下才初始化
        try {
            gapi.auth2.init({
                client_id: '368121835122-4tpffhrba2q7kd1hicnbm4cnpg01a4ac.apps.googleusercontent.com',
                scope: 'profile email',
                cookiepolicy: 'single_host_origin'
            }).then(() => {
                window.DebugLogger.log('Google认证初始化完成', window.DebugLogger.LOG_TYPE.AUTH);
                logAuthStatus('Google认证初始化完成');
                
                // 检查用户是否已经登录
                const auth2 = gapi.auth2.getAuthInstance();
                if (auth2.isSignedIn.get()) {
                    window.DebugLogger.log('检测到现有登录，正在自动登录...', window.DebugLogger.LOG_TYPE.AUTH);
                    logAuthStatus('检测到现有登录，正在自动登录...');
                    const googleUser = auth2.currentUser.get();
                    onSignIn(googleUser);
                }
            }).catch(error => {
                window.DebugLogger.log(`Google认证初始化失败: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
                    error: error.message,
                    stack: error.stack
                });
                
                logAuthStatus(`Google认证初始化失败: ${error.message}`);
            });
        } catch (error) {
            window.DebugLogger.log(`Google认证初始化异常: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
                error: error.message,
                stack: error.stack
            });
            logAuthStatus(`Google认证初始化异常: ${error.message}`);
        }
    });
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    try {
        // 延迟初始化，确保gapi已完全加载
        setTimeout(initGoogleAuth, 1000);
    } catch (error) {
        window.DebugLogger.log(`页面加载时发生错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
    }
}); 