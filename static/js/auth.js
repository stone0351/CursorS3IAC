// Google认证状态日志记录函数
function logAuthStatus(message, type = 'info') {
    const logsContainer = document.getElementById('auth-logs');
    const logItem = document.createElement('p');
    logItem.textContent = `${new Date().toLocaleTimeString()} - ${message}`;
    logItem.className = `log-item log-${type}`;
    logsContainer.appendChild(logItem);
    logsContainer.scrollTop = logsContainer.scrollHeight;
}

// 用户成功登录后的回调
function onSignIn(googleUser) {
    try {
        logAuthStatus('Google登录成功，正在获取用户信息...', 'info');
        
        // 获取用户基本信息
        const profile = googleUser.getBasicProfile();
        const id_token = googleUser.getAuthResponse().id_token;
        
        // 记录用户信息
        logAuthStatus(`用户ID: ${profile.getId()}`, 'info');
        logAuthStatus(`用户名: ${profile.getName()}`, 'info');
        logAuthStatus(`邮箱: ${profile.getEmail()}`, 'info');
        
        // 存储用户信息到本地存储
        localStorage.setItem('user_id', profile.getId());
        localStorage.setItem('user_name', profile.getName());
        localStorage.setItem('user_email', profile.getEmail());
        localStorage.setItem('id_token', id_token);
        
        logAuthStatus('正在向后端服务验证身份...', 'info');
        
        // 向后端API发送验证请求
        fetch('https://api.example.com/auth/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id_token })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('后端验证失败');
            }
            return response.json();
        })
        .then(data => {
            logAuthStatus('身份验证成功，正在加载用户数据...', 'success');
            
            // 显示登出按钮
            document.getElementById('signout-button').style.display = 'block';
            // 显示主内容
            document.getElementById('main-content').style.display = 'block';
            
            // 触发加载用户数据
            if (typeof loadUserData === 'function') {
                loadUserData();
            }
        })
        .catch(error => {
            logAuthStatus(`验证失败: ${error.message}`, 'error');
            signOut();
        });
    } catch (error) {
        logAuthStatus(`登录过程发生错误: ${error.message}`, 'error');
    }
}

// 退出登录
function signOut() {
    const auth2 = gapi.auth2.getAuthInstance();
    
    logAuthStatus('正在退出登录...', 'info');
    
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
        
        logAuthStatus('退出登录成功', 'success');
    }).catch(error => {
        logAuthStatus(`退出登录失败: ${error.message}`, 'error');
    });
}

// 初始化Google API客户端
function initGoogleAuth() {
    logAuthStatus('初始化Google认证...', 'info');
    
    gapi.load('auth2', () => {
        gapi.auth2.init({
            client_id: '368121835122-4tpffhrba2q7kd1hicnbm4cnpg01a4ac.apps.googleusercontent.com',
            scope: 'profile email'
        }).then(() => {
            logAuthStatus('Google认证初始化完成', 'success');
            
            // 检查用户是否已经登录
            const auth2 = gapi.auth2.getAuthInstance();
            if (auth2.isSignedIn.get()) {
                logAuthStatus('检测到现有登录，正在自动登录...', 'info');
                const googleUser = auth2.currentUser.get();
                onSignIn(googleUser);
            }
        }).catch(error => {
            logAuthStatus(`Google认证初始化失败: ${error.message}`, 'error');
        });
    });
}

// 页面加载完成后初始化
window.addEventListener('load', initGoogleAuth); 