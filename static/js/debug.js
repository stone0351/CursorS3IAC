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
    },
    
    /**
     * 渲染单条日志到UI
     * @param {Object} logItem - 日志项
     */
    renderLog: function(logItem) {
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
        debugContent.scrollTop = debugContent.scrollHeight;
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
        // 添加面板折叠/展开功能
        const toggleBtn = document.getElementById('debug-panel-toggle');
        const debugPanel = document.getElementById('debug-panel');
        
        if (toggleBtn && debugPanel) {
            toggleBtn.addEventListener('click', function() {
                debugPanel.classList.toggle('collapsed');
                toggleBtn.textContent = debugPanel.classList.contains('collapsed') ? '+' : '-';
            });
            
            // 点击面板标题也可以折叠/展开
            document.getElementById('debug-panel-header').addEventListener('click', function(e) {
                if (e.target !== toggleBtn) {
                    debugPanel.classList.toggle('collapsed');
                    toggleBtn.textContent = debugPanel.classList.contains('collapsed') ? '+' : '-';
                }
            });
        }
        
        // 添加初始日志
        this.log('调试面板已初始化', this.LOG_TYPE.AUTH);
        this.log('等待用户认证...', this.LOG_TYPE.AUTH);
    }
};

// 页面加载时初始化调试面板
document.addEventListener('DOMContentLoaded', function() {
    window.DebugLogger.init();
}); 