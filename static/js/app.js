// API基础URL
const API_BASE_URL = 'https://api.getmemap.com';

// 获取用户ID令牌
function getIdToken() {
    return localStorage.getItem('id_token');
}

// API请求函数
async function apiRequest(endpoint, method = 'GET', data = null) {
    // 记录API请求开始
    window.DebugLogger.log(`发起API请求: ${method} ${endpoint}`, window.DebugLogger.LOG_TYPE.API, {
        method,
        endpoint,
        data: method === 'POST' || method === 'PUT' ? '***' : null // 不显示敏感数据
    });
    
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getIdToken()}`
    };
    
    const options = {
        method,
        headers
    };
    
    if (data && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const startTime = Date.now();
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
        const endTime = Date.now();
        
        // 记录API请求完成
        window.DebugLogger.log(`API响应: ${response.status} (${endTime - startTime}ms)`, window.DebugLogger.LOG_TYPE.API, {
            status: response.status,
            statusText: response.statusText,
            time: `${endTime - startTime}ms`
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            
            // 记录API错误
            window.DebugLogger.log(`API错误: ${errorData.message || response.statusText}`, window.DebugLogger.LOG_TYPE.ERROR, {
                status: response.status,
                message: errorData.message || `API请求失败: ${response.status}`
            });
            
            throw new Error(errorData.message || `API请求失败: ${response.status}`);
        }
        
        const responseData = await response.json();
        
        // 记录Lambda执行
        window.DebugLogger.log(`Lambda函数执行: ${endpoint}`, window.DebugLogger.LOG_TYPE.LAMBDA, {
            endpoint,
            method,
            executionTime: `${endTime - startTime}ms`
        });
        
        return responseData;
    } catch (error) {
        console.error('API请求错误:', error);
        
        // 记录API错误
        window.DebugLogger.log(`API请求异常: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
        
        throw error;
    }
}

// 加载用户数据
async function loadUserData() {
    try {
        window.DebugLogger.log('开始加载用户数据', window.DebugLogger.LOG_TYPE.API);
        
        // 加载用户的AWS密钥
        await loadAwsKeys();
        // 加载用户的IAC代码
        await loadIacCodes();
        // 更新选择框
        updateSelects();
        
        window.DebugLogger.log('用户数据加载完成', window.DebugLogger.LOG_TYPE.API);
    } catch (error) {
        console.error('加载用户数据错误:', error);
        
        window.DebugLogger.log(`加载用户数据失败: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
        
        alert(`加载用户数据失败: ${error.message}`);
    }
}

// 加载用户的AWS密钥
async function loadAwsKeys() {
    try {
        window.DebugLogger.log('开始加载AWS密钥', window.DebugLogger.LOG_TYPE.API);
        window.DebugLogger.log('DynamoDB操作: 查询用户AWS密钥', window.DebugLogger.LOG_TYPE.DB);
        
        const keys = await apiRequest('/aws-keys');
        
        window.DebugLogger.log(`已加载${keys.length}个AWS密钥`, window.DebugLogger.LOG_TYPE.DB);
        
        const keyList = document.getElementById('key-list');
        keyList.innerHTML = '';
        
        if (keys.length === 0) {
            keyList.innerHTML = '<p>暂无保存的AWS密钥</p>';
            return;
        }
        
        keys.forEach(key => {
            const keyItem = document.createElement('div');
            keyItem.className = 'key-item';
            keyItem.innerHTML = `
                <div class="key-info">
                    <strong>${key.name}</strong> 
                    <span class="key-region">(${key.region})</span>
                </div>
                <div class="key-actions">
                    <button class="delete-btn" data-key-id="${key.id}">删除</button>
                </div>
            `;
            keyList.appendChild(keyItem);
            
            // 绑定删除按钮事件
            keyItem.querySelector('.delete-btn').addEventListener('click', function() {
                const keyId = this.getAttribute('data-key-id');
                deleteAwsKey(keyId);
            });
        });
        
        // 将密钥加入下拉列表
        const keySelect = document.getElementById('key-select');
        keySelect.innerHTML = '';
        
        keys.forEach(key => {
            const option = document.createElement('option');
            option.value = key.id;
            option.textContent = key.name;
            keySelect.appendChild(option);
        });
        
        window.DebugLogger.log('AWS密钥加载完成', window.DebugLogger.LOG_TYPE.API);
    } catch (error) {
        console.error('加载AWS密钥错误:', error);
        window.DebugLogger.log(`加载AWS密钥错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
        throw error;
    }
}

// 加载用户的IAC代码
async function loadIacCodes() {
    try {
        window.DebugLogger.log('开始加载IAC代码', window.DebugLogger.LOG_TYPE.API);
        window.DebugLogger.log('DynamoDB操作: 查询用户IAC代码', window.DebugLogger.LOG_TYPE.DB);
        
        const codes = await apiRequest('/iac-codes');
        
        window.DebugLogger.log(`已加载${codes.length}个IAC代码`, window.DebugLogger.LOG_TYPE.DB);
        
        const codeList = document.getElementById('code-list');
        codeList.innerHTML = '';
        
        if (codes.length === 0) {
            codeList.innerHTML = '<p>暂无保存的IAC代码</p>';
            return;
        }
        
        codes.forEach(code => {
            const codeItem = document.createElement('div');
            codeItem.className = 'code-item';
            codeItem.innerHTML = `
                <div class="code-info">
                    <strong>${code.name}</strong>
                </div>
                <div class="code-actions">
                    <button class="select-btn" data-code-id="${code.id}">查看</button>
                    <button class="delete-btn" data-code-id="${code.id}">删除</button>
                </div>
            `;
            codeList.appendChild(codeItem);
            
            // 绑定查看按钮事件
            codeItem.querySelector('.select-btn').addEventListener('click', function() {
                const codeId = this.getAttribute('data-code-id');
                viewIacCode(codeId);
            });
            
            // 绑定删除按钮事件
            codeItem.querySelector('.delete-btn').addEventListener('click', function() {
                const codeId = this.getAttribute('data-code-id');
                deleteIacCode(codeId);
            });
        });
        
        // 将代码加入下拉列表
        const codeSelect = document.getElementById('code-select');
        codeSelect.innerHTML = '';
        
        codes.forEach(code => {
            const option = document.createElement('option');
            option.value = code.id;
            option.textContent = code.name;
            codeSelect.appendChild(option);
        });
        
        window.DebugLogger.log('IAC代码加载完成', window.DebugLogger.LOG_TYPE.API);
    } catch (error) {
        console.error('加载IAC代码错误:', error);
        window.DebugLogger.log(`加载IAC代码错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
        throw error;
    }
}

// 查看IAC代码
async function viewIacCode(codeId) {
    try {
        window.DebugLogger.log(`查看IAC代码: ${codeId}`, window.DebugLogger.LOG_TYPE.API);
        window.DebugLogger.log('DynamoDB操作: 获取IAC代码详情', window.DebugLogger.LOG_TYPE.DB);
        
        const code = await apiRequest(`/iac-codes/${codeId}`);
        
        // 填充表单用于查看
        document.getElementById('code-name').value = code.name;
        document.getElementById('iac-code').value = code.code;
        
        window.DebugLogger.log('IAC代码加载完成', window.DebugLogger.LOG_TYPE.API);
    } catch (error) {
        console.error('查看IAC代码错误:', error);
        window.DebugLogger.log(`查看IAC代码错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
        alert(`查看IAC代码失败: ${error.message}`);
    }
}

// 删除AWS密钥
async function deleteAwsKey(keyId) {
    if (!confirm('确认删除此AWS密钥?')) {
        return;
    }
    
    try {
        window.DebugLogger.log(`删除AWS密钥: ${keyId}`, window.DebugLogger.LOG_TYPE.API);
        window.DebugLogger.log('DynamoDB操作: 删除AWS密钥', window.DebugLogger.LOG_TYPE.DB);
        
        await apiRequest(`/aws-keys/${keyId}`, 'DELETE');
        
        window.DebugLogger.log('AWS密钥删除成功', window.DebugLogger.LOG_TYPE.DB);
        
        await loadAwsKeys();  // 重新加载密钥列表
        updateSelects();
    } catch (error) {
        console.error('删除AWS密钥错误:', error);
        window.DebugLogger.log(`删除AWS密钥错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
        alert(`删除AWS密钥失败: ${error.message}`);
    }
}

// 删除IAC代码
async function deleteIacCode(codeId) {
    if (!confirm('确认删除此IAC代码?')) {
        return;
    }
    
    try {
        window.DebugLogger.log(`删除IAC代码: ${codeId}`, window.DebugLogger.LOG_TYPE.API);
        window.DebugLogger.log('DynamoDB操作: 删除IAC代码', window.DebugLogger.LOG_TYPE.DB);
        
        await apiRequest(`/iac-codes/${codeId}`, 'DELETE');
        
        window.DebugLogger.log('IAC代码删除成功', window.DebugLogger.LOG_TYPE.DB);
        
        await loadIacCodes();  // 重新加载代码列表
        updateSelects();
    } catch (error) {
        console.error('删除IAC代码错误:', error);
        window.DebugLogger.log(`删除IAC代码错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
        alert(`删除IAC代码失败: ${error.message}`);
    }
}

// 更新选择框
function updateSelects() {
    const keySelect = document.getElementById('key-select');
    const codeSelect = document.getElementById('code-select');
    
    if (keySelect.options.length === 0) {
        keySelect.innerHTML = '<option value="">暂无可用密钥</option>';
    }
    
    if (codeSelect.options.length === 0) {
        codeSelect.innerHTML = '<option value="">暂无可用代码</option>';
    }
}

// 执行IAC代码
async function executeIacCode(keyId, codeId) {
    try {
        window.DebugLogger.log(`开始执行IAC代码: ${codeId} (密钥: ${keyId})`, window.DebugLogger.LOG_TYPE.API);
        window.DebugLogger.log('Lambda函数调用: 执行IAC代码', window.DebugLogger.LOG_TYPE.LAMBDA);
        
        const startTime = Date.now();
        const results = await apiRequest('/execute', 'POST', {
            keyId,
            codeId
        });
        const endTime = Date.now();
        
        const executionTime = (endTime - startTime) / 1000; // 秒
        window.DebugLogger.log(`IAC代码执行完成 (耗时: ${executionTime.toFixed(2)}秒)`, window.DebugLogger.LOG_TYPE.LAMBDA, {
            execution_id: results.execution_id,
            success: results.success,
            executionTime: `${executionTime.toFixed(2)}秒`
        });
        
        const resultsOutput = document.getElementById('results-output');
        resultsOutput.textContent = results.output || '执行完成，无输出';
    } catch (error) {
        console.error('执行IAC代码错误:', error);
        
        window.DebugLogger.log(`执行IAC代码错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
            error: error.message,
            stack: error.stack
        });
        
        const resultsOutput = document.getElementById('results-output');
        resultsOutput.textContent = `执行错误: ${error.message}`;
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    // 注册AWS密钥表单提交事件
    const awsKeyForm = document.getElementById('aws-key-form');
    awsKeyForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        
        const keyName = document.getElementById('key-name').value;
        const accessKey = document.getElementById('access-key').value;
        const secretKey = document.getElementById('secret-key').value;
        const region = document.getElementById('region').value;
        
        try {
            window.DebugLogger.log(`保存AWS密钥: ${keyName}`, window.DebugLogger.LOG_TYPE.API);
            window.DebugLogger.log('DynamoDB操作: 创建AWS密钥', window.DebugLogger.LOG_TYPE.DB);
            
            await apiRequest('/aws-keys', 'POST', {
                name: keyName,
                accessKey,
                secretKey,
                region
            });
            
            window.DebugLogger.log('AWS密钥保存成功', window.DebugLogger.LOG_TYPE.DB);
            
            // 清空表单
            awsKeyForm.reset();
            
            // 重新加载密钥列表
            await loadAwsKeys();
            updateSelects();
            
            alert('AWS密钥已保存');
        } catch (error) {
            console.error('保存AWS密钥错误:', error);
            window.DebugLogger.log(`保存AWS密钥错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
                error: error.message,
                stack: error.stack
            });
            alert(`保存AWS密钥失败: ${error.message}`);
        }
    });
    
    // 注册IAC代码表单提交事件
    const iacCodeForm = document.getElementById('iac-code-form');
    iacCodeForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        
        const codeName = document.getElementById('code-name').value;
        const iacCode = document.getElementById('iac-code').value;
        
        try {
            window.DebugLogger.log(`保存IAC代码: ${codeName}`, window.DebugLogger.LOG_TYPE.API);
            window.DebugLogger.log('DynamoDB操作: 创建IAC代码', window.DebugLogger.LOG_TYPE.DB);
            
            await apiRequest('/iac-codes', 'POST', {
                name: codeName,
                code: iacCode
            });
            
            window.DebugLogger.log('IAC代码保存成功', window.DebugLogger.LOG_TYPE.DB);
            
            // 清空表单
            iacCodeForm.reset();
            
            // 重新加载代码列表
            await loadIacCodes();
            updateSelects();
            
            alert('IAC代码已保存');
        } catch (error) {
            console.error('保存IAC代码错误:', error);
            window.DebugLogger.log(`保存IAC代码错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
                error: error.message,
                stack: error.stack
            });
            alert(`保存IAC代码失败: ${error.message}`);
        }
    });
    
    // 注册执行表单提交事件
    const executionForm = document.getElementById('execution-form');
    executionForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        
        const keyId = document.getElementById('key-select').value;
        const codeId = document.getElementById('code-select').value;
        
        if (!keyId || !codeId) {
            alert('请选择AWS密钥和IAC代码');
            return;
        }
        
        try {
            const resultsOutput = document.getElementById('results-output');
            resultsOutput.textContent = '正在执行...';
            
            await executeIacCode(keyId, codeId);
        } catch (error) {
            console.error('执行IAC代码错误:', error);
            window.DebugLogger.log(`执行IAC代码错误: ${error.message}`, window.DebugLogger.LOG_TYPE.ERROR, {
                error: error.message,
                stack: error.stack
            });
            alert(`执行IAC代码失败: ${error.message}`);
        }
    });
}); 