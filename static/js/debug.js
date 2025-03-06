/**
 * 调试面板管理模块
 * 用于记录和显示系统各组件的运行状态
 */

// 全局调试日志对象
window.DebugLogger = {
    // 日志类型
    LOG_TYPE: {
        AUTH: 'auth',
        API: 'api',
        DB: 'db',
        LAMBDA: 'lambda',
        ERROR: 'error'
    },
    
    // 最大日志数
    MAX_LOGS: 100,
    
    // 日志列表
    logs: [],
    
    /**
     * 添加调试日志
     * @param {string} message - 日志消息
     * @param {string} type - 日志类型
     * @param {Object} details - 详细信息（可选）
     */
    log: function(message, type, details = null) {
        try {
            const timestamp = new Date().toLocaleTimeString();
            const logItem = {
                id: Date.now() + Math.random().toString(36).substr(2, 5),
                timestamp: timestamp,
                message: message,
                type: type,
                details: details
            };
            
            this.logs.push(logItem);
            
            // 限制日志数量
            if (this.logs.length > this.MAX_LOGS) {
                this.logs.shift();
            }
            
            // 渲染日志
            this.renderLog(logItem);
            
            // 控制台输出（方便开发者查看）
            console.log(`[${type.toUpperCase()}] ${timestamp} - ${message}`, details);
        } catch (error) {
            console.error('调试日志记录失败:', error);
        }
    },
    
    /**
     * 渲染单条日志到UI
     * @param {Object} logItem - 日志项
     */
    renderLog: function(logItem) {
        try {
            const logsList = document.getElementById('debug-logs');
            if (!logsList) return;
            
            const logElement = document.createElement('li');
            logElement.className = `debug-log-item debug-log-${logItem.type}`;
            logElement.setAttribute('data-log-id', logItem.id);
            
            // 构建日志内容
            let logContent = `[${logItem.timestamp}] ${logItem.message}`;
            
            // 如果有详细信息，添加展开/折叠功能
            if (logItem.details) {
                logContent += `\n${typeof logItem.details === 'object' ? JSON.stringify(logItem.details, null, 2) : logItem.details}`;
            }
            
            logElement.textContent = logContent;
            logsList.appendChild(logElement);
            
            // 滚动到最新日志
            const debugContent = document.getElementById('debug-panel-content');
            if (debugContent) {
                debugContent.scrollTop = debugContent.scrollHeight;
            }
        } catch (error) {
            console.error('调试日志渲染失败:', error);
        }
    },
    
    /**
     * 清除所有日志
     */
    clearLogs: function() {
        this.logs = [];
        const logsList = document.getElementById('debug-logs');
        if (logsList) {
            logsList.innerHTML = '';
        }
    },
    
    /**
     * 初始化调试面板
     */
    init: function() {
        try {
            // 添加面板折叠/展开功能
            const toggleBtn = document.getElementById('debug-panel-toggle');
            const debugPanel = document.getElementById('debug-panel');
            
            if (toggleBtn && debugPanel) {
                toggleBtn.addEventListener('click', function() {
                    debugPanel.classList.toggle('collapsed');
                    toggleBtn.textContent = debugPanel.classList.contains('collapsed') ? '+' : '-';
                });
                
                // 点击面板标题也可以折叠/展开
                const panelHeader = document.getElementById('debug-panel-header');
                if (panelHeader) {
                    panelHeader.addEventListener('click', function(e) {
                        if (e.target !== toggleBtn) {
                            debugPanel.classList.toggle('collapsed');
                            toggleBtn.textContent = debugPanel.classList.contains('collapsed') ? '+' : '-';
                        }
                    });
                }
            }
            
            // 设置全局错误处理
            this.setupGlobalErrorHandling();
            
            // 添加初始日志
            this.log('调试面板已初始化', this.LOG_TYPE.AUTH);
            this.log('等待用户认证...', this.LOG_TYPE.AUTH);
        } catch (error) {
            console.error('调试面板初始化失败:', error);
        }
    },
    
    /**
     * 设置全局错误处理
     */
    setupGlobalErrorHandling: function() {
        // 捕获全局未处理的错误
        window.onerror = (message, source, lineno, colno, error) => {
            this.log(`全局错误: ${message}`, this.LOG_TYPE.ERROR, {
                source: source,
                line: lineno, 
                column: colno,
                stack: error ? error.stack : null
            });
            return false; // 让浏览器继续处理错误
        };
        
        // 捕获未处理的Promise拒绝
        window.addEventListener('unhandledrejection', (event) => {
            this.log(`未处理的Promise拒绝: ${event.reason}`, this.LOG_TYPE.ERROR, {
                reason: event.reason,
                stack: event.reason && event.reason.stack ? event.reason.stack : null
            });
        });
        
        // 监控XHR/Fetch错误
        const originalFetch = window.fetch;
        window.fetch = (...args) => {
            return originalFetch(...args).catch(error => {
                this.log(`Fetch请求失败: ${error.message}`, this.LOG_TYPE.ERROR, {
                    url: args[0],
                    options: args[1],
                    error: error.message,
                    stack: error.stack
                });
                throw error;
            });
        };
    },
    
    /**
     * 获取系统状态概览
     */
    getSystemStatus: function() {
        const authLogs = this.logs.filter(log => log.type === this.LOG_TYPE.AUTH);
        const apiLogs = this.logs.filter(log => log.type === this.LOG_TYPE.API);
        const errorLogs = this.logs.filter(log => log.type === this.LOG_TYPE.ERROR);
        
        return {
            totalLogs: this.logs.length,
            authLogs: authLogs.length,
            apiLogs: apiLogs.length,
            errorLogs: errorLogs.length,
            lastError: errorLogs.length > 0 ? errorLogs[errorLogs.length - 1] : null,
            isLoggedIn: localStorage.getItem('id_token') !== null
        };
    }
};

// 页面加载时初始化调试面板
document.addEventListener('DOMContentLoaded', function() {
    try {
        window.DebugLogger.init();
    } catch (error) {
        console.error('调试面板加载失败:', error);
    }
}); 