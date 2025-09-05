
class JobManager {
    constructor() {
        this.jobId = this.getJobIdFromUrl();
        this.autoRefresh = true;
        this.refreshInterval = null;
        this.animatingProgress = false;
        this.currentProgress = 0;
        this.targetProgress = 0;
        this.progressStartTime = Date.now();
        this.lastProgressUpdate = Date.now();
        this.analysisStages = [
            { percent: 0, name: 'Initialize', icon: 'play', color: '#007bff' },
            { percent: 10, name: 'Validate', icon: 'file-upload', color: '#28a745' },
            { percent: 25, name: 'Extract', icon: 'file-archive', color: '#ffc107' },
            { percent: 40, name: 'Static Analysis', icon: 'code', color: '#17a2b8' },
            { percent: 65, name: 'Dynamic Analysis', icon: 'cogs', color: '#fd7e14' },
            { percent: 80, name: 'Network Analysis', icon: 'network-wired', color: '#6610f2' },
            { percent: 90, name: 'Security Scan', icon: 'shield-alt', color: '#e83e8c' },
            { percent: 100, name: 'Complete', icon: 'check-circle', color: '#28a745' }
        ];
        this.logContainer = null;
        this.logAutoScroll = true;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initProgressStages();
        this.initLogContainer();
        this.startAutoRefresh();
        this.updateProgressBars();
        this.handleAutoRefreshMeta();
        this.setupExpandableItems();
        this.setupRealTimeUpdates();
    }

    getJobIdFromUrl() {
        const pathParts = window.location.pathname.split('/');
        return pathParts[pathParts.length - 1] || pathParts[pathParts.length - 2];
    }

    setupEventListeners() {

        const refreshBtn = document.querySelector('[onclick="refreshJobStatus()"]');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.refreshJobStatus();
            });
        }

        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.stopAutoRefresh();
            } else {
                this.startAutoRefresh();
            }
        });

        window.addEventListener('beforeunload', () => {
            this.stopAutoRefresh();
        });
    }

    setupRealTimeUpdates() {

        this.startLiveUpdates();
    }

    startLiveUpdates() {

        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }

        const statusElement = document.querySelector('.status-banner');
        const isRunning = statusElement && statusElement.classList.contains('running');
        
        if (isRunning) {

            this.refreshInterval = setInterval(() => {
                this.refreshJobStatus(true); // silent refresh
            }, 2000);
        } else {

            this.refreshInterval = setInterval(() => {
                this.refreshJobStatus(true);
            }, 10000);
        }
    }

    initLogContainer() {

        let logCard = document.querySelector('.log-card');
        if (!logCard) {

            const jobInfoGrid = document.querySelector('.job-info-grid');
            if (jobInfoGrid) {
                logCard = this.createLogCard();
                jobInfoGrid.appendChild(logCard);
            }
        }
        
        this.logContainer = logCard ? logCard.querySelector('.log-entries') : null;

        this.setupLogControls();
    }

    createLogCard() {
        const logCard = document.createElement('div');
        logCard.className = 'info-card log-card';
        logCard.innerHTML = `
            <div class="card-header">
                <h3><i class="fas fa-list-alt"></i> Real-time Logs</h3>
                <div class="log-controls">
                    <button class="btn small secondary" onclick="jobManager.toggleAutoScroll()" id="auto-scroll-btn">
                        <i class="fas fa-arrow-down"></i> Auto-scroll
                    </button>
                    <button class="btn small secondary" onclick="jobManager.clearDisplayedLogs()">
                        <i class="fas fa-trash"></i> Clear
                    </button>
                </div>
            </div>
            <div class="card-content">
                <div class="log-container" id="live-log-container">
                    <div class="log-entries" id="live-log-entries"></div>
                    <div class="log-empty" id="log-empty-message" style="display: none;">
                        <i class="fas fa-info-circle"></i>
                        <p>No logs available yet. Logs will appear here during analysis.</p>
                    </div>
                </div>
            </div>
        `;
        return logCard;
    }

    setupLogControls() {
        const logContainer = document.getElementById('live-log-container');
        if (logContainer) {
            logContainer.addEventListener('scroll', () => {
                const isAtBottom = logContainer.scrollTop + logContainer.clientHeight >= logContainer.scrollHeight - 10;
                this.logAutoScroll = isAtBottom;
                this.updateAutoScrollButton();
            });
        }
    }

    updateAutoScrollButton() {
        const autoScrollBtn = document.getElementById('auto-scroll-btn');
        if (autoScrollBtn) {
            const icon = autoScrollBtn.querySelector('i');
            if (this.logAutoScroll) {
                icon.className = 'fas fa-arrow-down';
                autoScrollBtn.classList.add('active');
            } else {
                icon.className = 'fas fa-pause';
                autoScrollBtn.classList.remove('active');
            }
        }
    }

    toggleAutoScroll() {
        this.logAutoScroll = !this.logAutoScroll;
        this.updateAutoScrollButton();
        
        if (this.logAutoScroll && this.logContainer) {
            this.scrollToBottom();
        }
    }

    clearDisplayedLogs() {
        if (this.logContainer) {
            this.logContainer.innerHTML = '';
        }
        const emptyMessage = document.getElementById('log-empty-message');
        if (emptyMessage) {
            emptyMessage.style.display = 'block';
        }
    }

    scrollToBottom() {
        const logContainer = document.getElementById('live-log-container');
        if (logContainer) {
            logContainer.scrollTop = logContainer.scrollHeight;
        }
    }

    setupExpandableItems() {

        const logEntries = document.querySelectorAll('.log-entry');
        logEntries.forEach(entry => {
            const message = entry.querySelector('.log-message');
            if (message && message.textContent.length > 100) {
                message.style.cursor = 'pointer';
                message.title = 'Click to expand';
                
                let isExpanded = false;
                const originalText = message.textContent;
                const truncatedText = originalText.substring(0, 100) + '...';
                
                message.textContent = truncatedText;
                
                message.addEventListener('click', function() {
                    if (isExpanded) {
                        message.textContent = truncatedText;
                        message.title = 'Click to expand';
                    } else {
                        message.textContent = originalText;
                        message.title = 'Click to collapse';
                    }
                    isExpanded = !isExpanded;
                });
            }
        });

        this.initTooltips();
    }

    initTooltips() {
        const tooltipElements = document.querySelectorAll('[data-tooltip]');
        tooltipElements.forEach(el => {
            const tooltipText = el.getAttribute('data-tooltip');
            const tooltip = document.createElement('span');
            tooltip.className = 'tooltip-text';
            tooltip.textContent = tooltipText;
            
            el.classList.add('tooltip');
            el.appendChild(tooltip);
        });
    }

    initProgressStages() {
        const progressBar = document.getElementById('progress-bar');
        if (!progressBar) return;

        let progressStages = document.getElementById('progress-stages');
        if (!progressStages) {
            const progressSection = progressBar.closest('.progress-section') || progressBar.parentNode;
            
            const stagesContainer = document.createElement('div');
            stagesContainer.id = 'progress-stages';
            stagesContainer.className = 'progress-stages';

            const stageBar = document.createElement('div');
            stageBar.className = 'progress-stage-bar';
            stagesContainer.appendChild(stageBar);

            this.analysisStages.forEach((stage, index) => {
                const stageMarker = document.createElement('div');
                stageMarker.className = 'progress-stage';
                stageMarker.dataset.stage = index;
                stageMarker.dataset.percent = stage.percent;

                const icon = document.createElement('i');
                icon.className = `fas fa-${stage.icon}`;
                stageMarker.appendChild(icon);

                const label = document.createElement('div');
                label.className = 'progress-stage-label';
                label.textContent = stage.name;
                stageMarker.appendChild(label);
                
                stagesContainer.appendChild(stageMarker);
            });

            progressBar.parentNode.insertAdjacentElement('afterend', stagesContainer);
            progressStages = stagesContainer;
        }

        const progressContent = progressBar.closest('.progress-content');
        if (progressContent && !document.getElementById('progress-details')) {
            const detailsContainer = document.createElement('div');
            detailsContainer.id = 'progress-details';
            detailsContainer.className = 'progress-details';
            
            const statusElement = document.createElement('div');
            statusElement.id = 'progress-status';
            statusElement.className = 'progress-status';
            statusElement.textContent = 'Initializing...';
            
            const etaElement = document.createElement('div');
            etaElement.id = 'progress-eta';
            etaElement.className = 'progress-eta';
            etaElement.textContent = 'Estimating time remaining...';
            
            detailsContainer.appendChild(statusElement);
            detailsContainer.appendChild(etaElement);

            const progressText = progressContent.querySelector('.progress-text');
            if (progressText) {
                progressText.insertAdjacentElement('afterend', detailsContainer);
            } else {
                progressContent.appendChild(detailsContainer);
            }
        }
    }

    updateProgressStages(progress) {
        const stages = document.querySelectorAll('.progress-stage');
        if (!stages.length) return;
        
        stages.forEach(stage => {
            const stagePercent = parseInt(stage.dataset.percent);
            stage.classList.remove('active', 'completed');
            
            if (progress >= stagePercent) {
                stage.classList.add('completed');
            } else if (progress >= stagePercent - 15 && progress < stagePercent) {

                stage.classList.add('active');
            }
        });

        this.updateProgressStatus(progress);
    }

    updateProgressStatus(progress) {
        const statusElement = document.getElementById('progress-status');
        const etaElement = document.getElementById('progress-eta');
        if (!statusElement || !etaElement) return;

        let currentStage = this.analysisStages[0];
        for (let i = this.analysisStages.length - 1; i >= 0; i--) {
            if (progress >= this.analysisStages[i].percent) {

                const nextStage = this.analysisStages[i + 1];
                if (nextStage) {
                    currentStage = this.analysisStages[i];
                    const nextStageName = nextStage.name;
                    statusElement.textContent = `Processing: ${currentStage.name} → ${nextStageName}`;
                    break;
                } else {

                    statusElement.textContent = `Completing ${this.analysisStages[i].name}`;
                    break;
                }
            }
        }

        if (progress < 100) {
            const remainingPercent = 100 - progress;

            const estimatedSecondsPerPercent = 2;
            const secondsRemaining = remainingPercent * estimatedSecondsPerPercent;
            
            if (secondsRemaining > 60) {
                const minutes = Math.floor(secondsRemaining / 60);
                const seconds = Math.round(secondsRemaining % 60);
                etaElement.textContent = `Estimated time remaining: ~${minutes}m ${seconds}s`;
            } else {
                etaElement.textContent = `Estimated time remaining: ~${Math.round(secondsRemaining)}s`;
            }
        } else {
            etaElement.textContent = 'Processing complete!';
        }
    }

    handleAutoRefreshMeta() {
        const autoRefreshMeta = document.getElementById('auto-refresh');
        if (autoRefreshMeta) {
            const jobStatus = this.getJobStatus();

            if (['completed', 'failed', 'error', 'cancelled'].includes(jobStatus)) {
                autoRefreshMeta.remove();
                this.autoRefresh = false;
            }
        }
    }

    getJobStatus() {
        const statusBanner = document.querySelector('.status-banner');
        if (statusBanner) {
            const classes = statusBanner.className.split(' ');
            return classes.find(cls => ['running', 'completed', 'failed', 'error', 'cancelled'].includes(cls)) || 'unknown';
        }
        return 'unknown';
    }

    startAutoRefresh() {
        if (!this.autoRefresh) return;

        const jobStatus = this.getJobStatus();

        if (jobStatus === 'running') {
            this.refreshInterval = setInterval(() => {
                this.refreshJobStatus();
            }, 2000); // Refresh every 2 seconds for better responsiveness
        }
    }

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    async refreshJobStatus() {
        try {
            const response = await fetch(`/api/job/${this.jobId}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
                }
            });

            if (response.ok) {
                const jobData = await response.json();
                
                if (jobData.success && jobData.data) {
                    this.updateJobDisplay(jobData.data);

                    if (!['running', 'pending'].includes(jobData.data.status)) {
                        this.stopAutoRefresh();
                        setTimeout(() => {
                            location.reload();
                        }, 2000);
                    }
                } else {
                    console.error('Failed to fetch job status:', jobData.error || 'Unknown error');
                }
            } else {
                console.error('Failed to fetch job status');
            }
        } catch (error) {
            console.error('Error refreshing job status:', error);
        }
    }

    updateJobDisplay(jobData) {

        const progressBar = document.getElementById('progress-bar');
        const progressText = document.getElementById('progress-text');
        
        if (progressBar && jobData.progress !== undefined) {
            this.targetProgress = jobData.progress;
            
            if (!this.animatingProgress) {
                this.animateProgress();
            }
        }
        
        if (progressText && jobData.progress !== undefined) {
            const task = jobData.current_task ? ` — ${jobData.current_task}` : '';
            progressText.textContent = jobData.progress + '% Complete' + task;
        }

        if (jobData.log && Array.isArray(jobData.log)) {
            this.updateLiveLogs(jobData.log);
        }

        const statusBanner = document.querySelector('.status-banner');
        if (statusBanner && jobData.status) {
            const currentStatus = this.getJobStatus();
            if (currentStatus !== jobData.status) {

                if (jobData.status === 'completed') {
                    const event = new CustomEvent('analysisComplete', { detail: jobData });
                    document.dispatchEvent(event);
                }

                location.reload();
            }
        }

        if (jobData.type === 'batch' && jobData.results) {
            this.updateBatchResults(jobData);
        }
    }

    updateLiveLogs(logs) {
        if (!this.logContainer) {
            return;
        }

        this.logContainer.innerHTML = '';
        
        const emptyMessage = document.getElementById('log-empty-message');
        if (logs.length === 0) {
            if (emptyMessage) {
                emptyMessage.style.display = 'block';
            }
            return;
        }

        if (emptyMessage) {
            emptyMessage.style.display = 'none';
        }

        logs.forEach((logEntry, index) => {
            const logElement = this.createLogElement(logEntry, index);
            this.logContainer.appendChild(logElement);
        });

        if (this.logAutoScroll) {
            this.scrollToBottom();
        }
    }

    createLogElement(logEntry, index) {
        const logDiv = document.createElement('div');
        logDiv.className = `log-entry ${logEntry.level || 'info'}`;
        logDiv.dataset.index = index;

        const timestamp = new Date(logEntry.time * 1000).toLocaleTimeString();
        const message = logEntry.message || 'No message';
        const progress = logEntry.progress !== undefined ? ` (${logEntry.progress}%)` : '';
        const levelIcon = this.getLevelIcon(logEntry.level || 'info');

        logDiv.innerHTML = `
            <div class="log-header">
                <span class="log-time">${timestamp}</span>
                <span class="log-level">
                    <i class="${levelIcon}"></i>
                    ${(logEntry.level || 'info').toUpperCase()}${progress}
                </span>
            </div>
            <div class="log-message">${this.escapeHtml(message)}</div>
        `;

        return logDiv;
    }

    getLevelIcon(level) {
        const icons = {
            'info': 'fas fa-info-circle',
            'success': 'fas fa-check-circle',
            'warning': 'fas fa-exclamation-triangle',
            'error': 'fas fa-times-circle',
            'debug': 'fas fa-bug'
        };
        return icons[level] || icons['info'];
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    animateProgress() {
        this.animatingProgress = true;
        
        const progressBar = document.getElementById('progress-bar');
        if (!progressBar) {
            this.animatingProgress = false;
            return;
        }
        
        const animate = () => {
            if (Math.abs(this.currentProgress - this.targetProgress) < 0.5) {
                this.currentProgress = this.targetProgress;
                progressBar.style.width = this.currentProgress + '%';
                this.updateProgressStages(this.currentProgress);
                this.animatingProgress = false;
                return;
            }

            this.currentProgress += (this.targetProgress - this.currentProgress) * 0.2;
            progressBar.style.width = this.currentProgress + '%';
            this.updateProgressStages(this.currentProgress);
            
            requestAnimationFrame(animate);
        };
        
        requestAnimationFrame(animate);
    }

    updateBatchResults(jobData) {

        const completedCard = document.querySelector('.summary-card .summary-value.success');
        const failedCard = document.querySelector('.summary-card .summary-value.error');
        
        if (completedCard) {
            completedCard.textContent = jobData.completed || 0;
        }
        
        if (failedCard) {
            failedCard.textContent = jobData.failed || 0;
        }
    }

    updateProgressBars() {
        const progressBars = document.querySelectorAll('.progress[data-progress]');
        progressBars.forEach(bar => {
            const progress = parseInt(bar.dataset.progress) || 0;
            this.currentProgress = progress;
            this.targetProgress = progress;
            bar.style.width = progress + '%';
            this.updateProgressStages(progress);

            const progressText = document.getElementById('progress-text');
            if (progressText) {
                const task = bar.dataset.currentTask ? ` — ${bar.dataset.currentTask}` : '';
                progressText.textContent = progress + '% Complete' + task;
            }
        });
    }
}

window.cancelJob = async function(jobId) {
    if (!confirm('Are you sure you want to cancel this job?')) {
        return;
    }

    const cancelBtn = document.getElementById('cancel-btn');
    if (cancelBtn) {
        cancelBtn.disabled = true;
        cancelBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cancelling...';
    }

    try {
        const response = await fetch(`/api/job/${jobId}/cancel`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
            }
        });

        const data = await response.json();
        
        if (data.success) {
            showNotification('Job cancelled successfully', 'success');
            setTimeout(() => location.reload(), 1500);
        } else {
            showNotification('Failed to cancel job: ' + (data.error || 'Unknown error'), 'error');
            if (cancelBtn) {
                cancelBtn.disabled = false;
                cancelBtn.innerHTML = '<i class="fas fa-stop"></i> Cancel Job';
            }
        }
    } catch (error) {
        console.error('Error cancelling job:', error);
        showNotification('Failed to cancel job', 'error');
        if (cancelBtn) {
            cancelBtn.disabled = false;
            cancelBtn.innerHTML = '<i class="fas fa-stop"></i> Cancel Job';
        }
    }
};

window.deleteJob = async function(jobId) {
    if (!confirm('Are you sure you want to delete this job? This action cannot be undone.')) {
        return;
    }

    const deleteBtn = document.getElementById('delete-btn');
    if (deleteBtn) {
        deleteBtn.disabled = true;
        deleteBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Deleting...';
    }

    try {
        const response = await fetch(`/api/job/${jobId}/delete`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content')
            }
        });

        const data = await response.json();
        
        if (data.success) {
            showNotification('Job deleted successfully', 'success');
            setTimeout(() => {
                window.location.href = '/jobs';
            }, 1500);
        } else {
            showNotification('Failed to delete job: ' + (data.error || 'Unknown error'), 'error');
            if (deleteBtn) {
                deleteBtn.disabled = false;
                deleteBtn.innerHTML = '<i class="fas fa-trash"></i> Delete Job';
            }
        }
    } catch (error) {
        console.error('Error deleting job:', error);
        showNotification('Failed to delete job', 'error');
        if (deleteBtn) {
            deleteBtn.disabled = false;
            deleteBtn.innerHTML = '<i class="fas fa-trash"></i> Delete Job';
        }
    }
};

window.refreshJobStatus = function() {
    if (window.jobManager) {
        window.jobManager.refreshJobStatus();
    } else {
        location.reload();
    }
};

window.showNotification = function(message, type = 'info') {

    let notificationContainer = document.getElementById('notification-container');
    if (!notificationContainer) {
        notificationContainer = document.createElement('div');
        notificationContainer.id = 'notification-container';
        notificationContainer.style.position = 'fixed';
        notificationContainer.style.top = '20px';
        notificationContainer.style.right = '20px';
        notificationContainer.style.zIndex = '1000';
        document.body.appendChild(notificationContainer);
    }

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-icon">
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
        </div>
        <div class="notification-content">
            <div class="notification-message">${message}</div>
        </div>
        <button class="notification-close">
            <i class="fas fa-times"></i>
        </button>
    `;

    notification.style.display = 'flex';
    notification.style.alignItems = 'center';
    notification.style.gap = '10px';
    notification.style.background = 'white';
    notification.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.15)';
    notification.style.borderRadius = '8px';
    notification.style.padding = '12px 16px';
    notification.style.marginBottom = '10px';
    notification.style.borderLeft = `4px solid ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'}`;
    notification.style.animation = 'slideInRight 0.3s forwards';

    notificationContainer.appendChild(notification);

    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => {
        notification.style.animation = 'slideOutRight 0.3s forwards';
        setTimeout(() => {
            notificationContainer.removeChild(notification);
        }, 300);
    });

    setTimeout(() => {
        if (notification.parentNode === notificationContainer) {
            notification.style.animation = 'slideOutRight 0.3s forwards';
            setTimeout(() => {
                if (notification.parentNode === notificationContainer) {
                    notificationContainer.removeChild(notification);
                }
            }, 300);
        }
    }, 5000);

    if (!document.getElementById('notification-animations')) {
        const style = document.createElement('style');
        style.id = 'notification-animations';
        style.textContent = `
            @keyframes slideInRight {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOutRight {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    }
};

document.addEventListener('DOMContentLoaded', function() {
    window.jobManager = new JobManager();

    const reportLinks = document.querySelectorAll('a[href*="/report/"]');
    reportLinks.forEach(link => {
        link.addEventListener('click', function(e) {

            if (this.href.includes('download=1')) {
                const btn = this;
                const originalText = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Downloading...';
                btn.disabled = true;
                
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    btn.disabled = false;
                }, 3000);
            }
        });
    });

    const jobIdElements = document.querySelectorAll('.job-id code, .job-id-code');
    jobIdElements.forEach(element => {
        element.style.cursor = 'pointer';
        element.title = 'Click to copy job ID';
        
        element.addEventListener('click', function() {
            const jobId = this.textContent;
            
            if (navigator.clipboard) {
                navigator.clipboard.writeText(jobId).then(() => {
                    showNotification('Job ID copied to clipboard', 'success');
                });
            } else {

                const textArea = document.createElement('textarea');
                textArea.value = jobId;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showNotification('Job ID copied to clipboard', 'success');
            }
        });
    });
});

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { JobManager };
}
