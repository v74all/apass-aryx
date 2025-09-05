
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
        this.lastLogCount = 0;
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
        this.lastLogCount = 0;
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
                stageMarker.style.left = `${stage.percent}%`;

                const icon = document.createElement('i');
                icon.className = `fas fa-${stage.icon}`;
                icon.style.color = stage.color;
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
            statusElement.innerHTML = '<i class="fas fa-clock"></i> Initializing...';
            
            const etaElement = document.createElement('div');
            etaElement.id = 'progress-eta';
            etaElement.className = 'progress-eta';
            etaElement.innerHTML = '<i class="fas fa-hourglass-half"></i> Estimating time remaining...';
            
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
        
        if (!statusElement) return;

        let currentStage = null;
        for (let i = this.analysisStages.length - 1; i >= 0; i--) {
            if (progress >= this.analysisStages[i].percent) {
                currentStage = this.analysisStages[i];
                break;
            }
        }
        
        if (currentStage) {
            statusElement.innerHTML = `<i class="fas fa-${currentStage.icon}"></i> ${currentStage.name}`;
        }

        if (etaElement && progress > 0) {
            const elapsed = Date.now() - this.progressStartTime;
            const rate = progress / elapsed;
            const remaining = (100 - progress) / rate;
            
            if (remaining > 0 && remaining < Infinity) {
                const minutes = Math.floor(remaining / 60000);
                const seconds = Math.floor((remaining % 60000) / 1000);
                etaElement.innerHTML = `<i class="fas fa-hourglass-half"></i> ETA: ${minutes}m ${seconds}s`;
            } else {
                etaElement.innerHTML = '<i class="fas fa-hourglass-half"></i> Calculating...';
            }
        }
    }

    updateProgressBars() {
        const progressBar = document.getElementById('progress-bar');
        if (!progressBar) return;

        const progress = parseInt(progressBar.dataset.progress) || 0;
        const currentTask = progressBar.dataset.currentTask || 'Processing...';
        
        if (progress !== this.currentProgress) {
            this.animateProgress(this.currentProgress, progress);
            this.currentProgress = progress;
        }

        const progressText = document.getElementById('progress-text');
        if (progressText) {
            progressText.textContent = `${progress}% Complete — ${currentTask}`;
        }

        this.updateProgressStages(progress);
    }

    animateProgress(fromProgress, toProgress) {
        if (this.animatingProgress) return;
        
        this.animatingProgress = true;
        const progressBar = document.getElementById('progress-bar');
        if (!progressBar) {
            this.animatingProgress = false;
            return;
        }
        
        const duration = 800; // Animation duration in ms
        const startTime = Date.now();
        const diff = toProgress - fromProgress;
        
        const animate = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);

            const easeOut = 1 - Math.pow(1 - progress, 3);
            const currentProgress = fromProgress + (diff * easeOut);
            
            progressBar.style.width = `${currentProgress}%`;
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            } else {
                this.animatingProgress = false;
                progressBar.style.width = `${toProgress}%`;
            }
        };
        
        requestAnimationFrame(animate);
    }

    handleAutoRefreshMeta() {
        const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
        if (metaRefresh) {
            const content = metaRefresh.getAttribute('content');
            const refreshTime = parseInt(content.split(';')[0]) * 1000;
            
            setTimeout(() => {
                if (this.autoRefresh) {
                    window.location.reload();
                }
            }, refreshTime);
        }
    }

    getJobStatus() {
        const statusElement = document.querySelector('.status-banner');
        if (statusElement) {
            if (statusElement.classList.contains('running')) return 'running';
            if (statusElement.classList.contains('completed')) return 'completed';
            if (statusElement.classList.contains('failed') || statusElement.classList.contains('error')) return 'failed';
            if (statusElement.classList.contains('cancelled')) return 'cancelled';
        }
        return 'unknown';
    }

    startAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        
        const status = this.getJobStatus();
        if (status === 'running') {
            this.refreshInterval = setInterval(() => {
                this.refreshJobStatus(true);
            }, 3000);
        } else if (status !== 'unknown') {

            this.stopAutoRefresh();
        }
    }

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    async refreshJobStatus(silent = false) {
        try {
            if (!silent) {
                this.showRefreshingIndicator();
            }
            
            const response = await fetch(`/api/job/${this.jobId}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (data.success && data.data) {
                this.updateJobDisplay(data.data);
                
                if (!silent) {
                    this.showRefreshSuccess();
                }
            } else {
                throw new Error(data.error || 'Failed to get job status');
            }
            
        } catch (error) {
            console.error('Failed to refresh job status:', error);
            
            if (!silent) {
                this.showRefreshError(error.message);
            }
        }
    }

    updateJobDisplay(jobData) {

        if (jobData.progress !== undefined) {
            const progressBar = document.getElementById('progress-bar');
            if (progressBar) {
                progressBar.dataset.progress = jobData.progress;
                progressBar.dataset.currentTask = jobData.current_task || 'Processing...';
                this.updateProgressBars();
            }

            const progressText = document.getElementById('progress-text');
            if (progressText) {
                const icon = jobData.current_icon ? `<i class="${jobData.current_icon}"></i> ` : '';
                progressText.innerHTML = `${icon}${jobData.progress}% Complete — ${jobData.current_task || 'Processing...'}`;
            }
        }

        this.updateStatusBanner(jobData);

        this.updateLogs(jobData.log || []);

        this.updateJobInfo(jobData);

        if (jobData.status !== 'running' && this.refreshInterval) {
            this.stopAutoRefresh();
        } else if (jobData.status === 'running' && !this.refreshInterval) {
            this.startAutoRefresh();
        }
    }

    updateStatusBanner(jobData) {
        const statusBanner = document.querySelector('.status-banner');
        if (!statusBanner) return;

        statusBanner.classList.remove('running', 'completed', 'failed', 'error', 'cancelled');

        if (jobData.status) {
            statusBanner.classList.add(jobData.status);
        }

        const statusIcon = statusBanner.querySelector('.status-icon i');
        if (statusIcon && jobData.current_icon) {
            statusIcon.className = jobData.current_icon;
        }

        const statusInfo = statusBanner.querySelector('.status-info h2');
        if (statusInfo) {
            statusInfo.textContent = jobData.status ? jobData.status.charAt(0).toUpperCase() + jobData.status.slice(1) : 'Unknown';
        }
        
        const statusDesc = statusBanner.querySelector('.status-info p');
        if (statusDesc && jobData.current_task) {
            statusDesc.textContent = jobData.current_task;
        }
    }

    updateLogs(logs) {
        if (!this.logContainer) return;
        
        const emptyMessage = document.getElementById('log-empty-message');
        
        if (!logs || logs.length === 0) {
            if (emptyMessage) {
                emptyMessage.style.display = 'block';
            }
            return;
        }
        
        if (emptyMessage) {
            emptyMessage.style.display = 'none';
        }

        if (logs.length > this.lastLogCount) {
            const newLogs = logs.slice(this.lastLogCount);
            
            newLogs.forEach(logEntry => {
                const logElement = this.createLogElement(logEntry);
                this.logContainer.appendChild(logElement);
            });
            
            this.lastLogCount = logs.length;

            if (this.logAutoScroll) {
                this.scrollToBottom();
            }
        }
    }

    createLogElement(logEntry) {
        const logDiv = document.createElement('div');
        logDiv.className = `log-entry ${logEntry.level || 'info'}`;
        
        const timestamp = new Date(logEntry.time * 1000).toLocaleTimeString();
        const level = logEntry.level || 'info';
        const message = logEntry.message || 'No message';
        const progress = logEntry.progress ? ` (${logEntry.progress}%)` : '';

        let icon = 'fa-info-circle';
        switch (level) {
            case 'error': icon = 'fa-exclamation-triangle'; break;
            case 'warning': icon = 'fa-exclamation-circle'; break;
            case 'success': icon = 'fa-check-circle'; break;
            case 'debug': icon = 'fa-bug'; break;
            default: icon = 'fa-info-circle'; break;
        }
        
        logDiv.innerHTML = `
            <div class="log-timestamp">${timestamp}</div>
            <div class="log-icon"><i class="fas ${icon}"></i></div>
            <div class="log-content">
                <div class="log-message">${message}${progress}</div>
                ${logEntry.stage ? `<div class="log-stage">Stage ${logEntry.stage}</div>` : ''}
            </div>
        `;
        
        return logDiv;
    }

    updateJobInfo(jobData) {

        const durationElement = document.querySelector('.info-row .value');
        if (durationElement && jobData.created_at && jobData.updated_at) {
            const duration = this.formatDuration(jobData.created_at, jobData.updated_at);

            const durationRows = document.querySelectorAll('.info-row');
            durationRows.forEach(row => {
                const label = row.querySelector('.label');
                if (label && label.textContent.includes('Duration')) {
                    const value = row.querySelector('.value');
                    if (value) value.textContent = duration;
                }
            });
        }
    }

    formatDuration(startTime, endTime) {
        const start = typeof startTime === 'number' ? startTime * 1000 : new Date(startTime).getTime();
        const end = typeof endTime === 'number' ? endTime * 1000 : new Date(endTime).getTime();
        const duration = Math.abs(end - start);
        
        const hours = Math.floor(duration / (1000 * 60 * 60));
        const minutes = Math.floor((duration % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((duration % (1000 * 60)) / 1000);
        
        if (hours > 0) {
            return `${hours}h ${minutes}m ${seconds}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds}s`;
        } else {
            return `${seconds}s`;
        }
    }

    showRefreshingIndicator() {
        const refreshBtn = document.querySelector('[onclick="refreshJobStatus()"]');
        if (refreshBtn) {
            const icon = refreshBtn.querySelector('i');
            if (icon) {
                icon.classList.add('fa-spin');
            }
        }
    }

    showRefreshSuccess() {
        const refreshBtn = document.querySelector('[onclick="refreshJobStatus()"]');
        if (refreshBtn) {
            const icon = refreshBtn.querySelector('i');
            if (icon) {
                icon.classList.remove('fa-spin');
                icon.classList.remove('fa-sync-alt');
                icon.classList.add('fa-check');
                
                setTimeout(() => {
                    icon.classList.remove('fa-check');
                    icon.classList.add('fa-sync-alt');
                }, 1000);
            }
        }
    }

    showRefreshError(message) {
        const refreshBtn = document.querySelector('[onclick="refreshJobStatus()"]');
        if (refreshBtn) {
            const icon = refreshBtn.querySelector('i');
            if (icon) {
                icon.classList.remove('fa-spin');
                icon.classList.remove('fa-sync-alt');
                icon.classList.add('fa-exclamation-triangle');
                icon.style.color = '#dc3545';
                
                setTimeout(() => {
                    icon.classList.remove('fa-exclamation-triangle');
                    icon.classList.add('fa-sync-alt');
                    icon.style.color = '';
                }, 2000);
            }
        }

        console.error('Refresh error:', message);
    }
}

function refreshJobStatus() {
    if (window.jobManager) {
        window.jobManager.refreshJobStatus();
    }
}

function cancelJob(jobId) {
    if (confirm('Are you sure you want to cancel this analysis job?')) {
        fetch(`/api/job/${jobId}/cancel`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Failed to cancel job: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(error => {
            console.error('Error canceling job:', error);
            alert('Failed to cancel job: ' + error.message);
        });
    }
}

function deleteJob(jobId) {
    if (confirm('Are you sure you want to delete this job? This action cannot be undone.')) {
        fetch(`/api/job/${jobId}/delete`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = '/jobs';
            } else {
                alert('Failed to delete job: ' + (data.error || 'Unknown error'));
            }
        })
        .catch(error => {
            console.error('Error deleting job:', error);
            alert('Failed to delete job: ' + error.message);
        });
    }
}

document.addEventListener('DOMContentLoaded', function() {
    window.jobManager = new JobManager();
});
