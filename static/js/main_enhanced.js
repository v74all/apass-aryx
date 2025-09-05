
const AppState = {
    currentTab: 'analyze',
    uploadQueue: [],
    dragDropEnabled: true,
    statusRefreshInterval: null,
    csrfToken: null
};

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {

    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta) {
        AppState.csrfToken = csrfMeta.content;
    }

    initializeNavigation();
    initializeTabs();
    initializeFileUploads();
    initializeDragDrop();
    initializeStatusDashboard();
    initializeRecentJobs();
    initializeFormValidation();
    initializeActionCards();

    if (window.location.hash === '#status') {
        switchToTab('status');
    }
    
    console.log('APASS ARYX Web Interface initialized');
}

function initializeNavigation() {
    const navToggle = document.querySelector('.nav-toggle');
    const navMenu = document.querySelector('.nav-menu');
    
    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
            navToggle.classList.toggle('active');
        });
    }

    document.addEventListener('click', function(e) {
        if (!e.target.closest('.nav-container')) {
            if (navMenu) navMenu.classList.remove('active');
            if (navToggle) navToggle.classList.remove('active');
        }
    });
}

function initializeTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabId = button.getAttribute('data-tab');
            switchToTab(tabId);
        });
    });
}

function switchToTab(tabId) {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    tabButtons.forEach(btn => btn.classList.remove('active'));
    tabPanes.forEach(pane => pane.classList.remove('active'));

    const activeButton = document.querySelector(`[data-tab="${tabId}"]`);
    const activePane = document.getElementById(tabId);
    
    if (activeButton && activePane) {
        activeButton.classList.add('active');
        activePane.classList.add('active');
        AppState.currentTab = tabId;

        handleTabSwitch(tabId);
    }
}

function handleTabSwitch(tabId) {
    switch(tabId) {
        case 'status':
            loadStatusData();
            break;
        case 'upload':
            initializeDragDropZone();
            break;
        default:
            break;
    }
}

function initializeFileUploads() {

    const singleFileInput = document.getElementById('apk_file');
    const singleUploadArea = document.getElementById('single-upload-area');
    
    if (singleFileInput && singleUploadArea) {
        singleUploadArea.addEventListener('click', () => singleFileInput.click());
        singleFileInput.addEventListener('change', handleSingleFileSelect);

        setupFileDragDrop(singleUploadArea, singleFileInput, false);
    }

    const batchFileInput = document.getElementById('apk_files');
    const batchUploadArea = document.getElementById('batch-upload-area');
    
    if (batchFileInput && batchUploadArea) {
        batchUploadArea.addEventListener('click', () => batchFileInput.click());
        batchFileInput.addEventListener('change', handleBatchFileSelect);

        setupFileDragDrop(batchUploadArea, batchFileInput, true);
    }
}

function setupFileDragDrop(area, input, multiple) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        area.addEventListener(eventName, preventDefaults, false);
    });
    
    ['dragenter', 'dragover'].forEach(eventName => {
        area.addEventListener(eventName, () => area.classList.add('dragover'), false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        area.addEventListener(eventName, () => area.classList.remove('dragover'), false);
    });
    
    area.addEventListener('drop', (e) => handleFileDrop(e, input, multiple), false);
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function handleFileDrop(e, input, multiple) {
    const files = Array.from(e.dataTransfer.files);
    const apkFiles = files.filter(file => file.name.toLowerCase().endsWith('.apk'));
    
    if (apkFiles.length === 0) {
        showNotification('Please drop only APK files', 'error');
        return;
    }
    
    if (!multiple && apkFiles.length > 1) {
        showNotification('Please drop only one APK file for single analysis', 'warning');
        return;
    }

    const dt = new DataTransfer();
    apkFiles.forEach(file => dt.items.add(file));
    input.files = dt.files;

    input.dispatchEvent(new Event('change'));
}

function handleSingleFileSelect(e) {
    const file = e.target.files[0];
    const fileInfo = document.getElementById('single-file-info');
    
    if (file) {
        if (!validateApkFile(file)) return;
        
        displayFileInfo(fileInfo, file);
        fileInfo.style.display = 'flex';

        const removeBtn = fileInfo.querySelector('.remove-file');
        if (removeBtn) {
            removeBtn.onclick = () => {
                e.target.value = '';
                fileInfo.style.display = 'none';
            };
        }
    }
}

function handleBatchFileSelect(e) {
    const files = Array.from(e.target.files);
    const filesList = document.getElementById('batch-files-list');
    
    if (files.length === 0) return;

    const validFiles = files.filter(validateApkFile);
    if (validFiles.length !== files.length) {
        showNotification(`${files.length - validFiles.length} invalid files were removed`, 'warning');
    }

    displayBatchFilesList(filesList, validFiles);
    filesList.style.display = 'block';
}

function displayFileInfo(container, file) {
    const fileName = container.querySelector('.file-name');
    const fileSize = container.querySelector('.file-size');
    
    if (fileName) fileName.textContent = file.name;
    if (fileSize) fileSize.textContent = formatFileSize(file.size);
}

function displayBatchFilesList(container, files) {
    if (!container) return;
    
    container.innerHTML = '';
    
    files.forEach((file, index) => {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        fileItem.innerHTML = `
            <div class="file-info">
                <i class="fas fa-file-archive"></i>
                <div>
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${formatFileSize(file.size)}</div>
                </div>
            </div>
            <button type="button" class="remove-file" onclick="removeBatchFile(${index})">
                <i class="fas fa-times"></i>
            </button>
        `;
        container.appendChild(fileItem);
    });
}

function initializeDragDrop() {
    const dragFiles = document.getElementById('drag-files');
    if (dragFiles) {
        dragFiles.addEventListener('change', handleDragDropFiles);
    }
}

function initializeDragDropZone() {
    const dragDropZone = document.getElementById('drag-drop-zone');
    if (!dragDropZone) return;
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dragDropZone.addEventListener(eventName, preventDefaults, false);
    });
    
    ['dragenter', 'dragover'].forEach(eventName => {
        dragDropZone.addEventListener(eventName, () => {
            dragDropZone.classList.add('dragover');
        }, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        dragDropZone.addEventListener(eventName, () => {
            dragDropZone.classList.remove('dragover');
        }, false);
    });
    
    dragDropZone.addEventListener('drop', handleDragDropZoneDrop, false);
}

function handleDragDropZoneDrop(e) {
    const files = Array.from(e.dataTransfer.files);
    const apkFiles = files.filter(file => file.name.toLowerCase().endsWith('.apk'));
    
    if (apkFiles.length === 0) {
        showNotification('Please drop only APK files', 'error');
        return;
    }
    
    addFilesToQueue(apkFiles);
}

function handleDragDropFiles(e) {
    const files = Array.from(e.target.files);
    addFilesToQueue(files);
}

function addFilesToQueue(files) {
    const validFiles = files.filter(validateApkFile);
    AppState.uploadQueue.push(...validFiles);
    
    updateQueueDisplay();
    showNotification(`Added ${validFiles.length} files to queue`, 'success');
}

function updateQueueDisplay() {
    const uploadQueue = document.getElementById('upload-queue');
    const queueList = document.getElementById('queue-list');
    
    if (!uploadQueue || !queueList) return;
    
    if (AppState.uploadQueue.length === 0) {
        uploadQueue.style.display = 'none';
        return;
    }
    
    uploadQueue.style.display = 'block';
    queueList.innerHTML = '';
    
    AppState.uploadQueue.forEach((file, index) => {
        const queueItem = document.createElement('div');
        queueItem.className = 'queue-item';
        queueItem.innerHTML = `
            <i class="fas fa-file-archive"></i>
            <div class="queue-item-info">
                <div class="queue-item-name">${file.name}</div>
                <div class="queue-item-size">${formatFileSize(file.size)}</div>
            </div>
            <button type="button" class="btn small danger" onclick="removeFromQueue(${index})">
                <i class="fas fa-trash"></i>
            </button>
        `;
        queueList.appendChild(queueItem);
    });
}

function initializeStatusDashboard() {

    AppState.statusRefreshInterval = setInterval(() => {
        if (AppState.currentTab === 'status') {
            loadStatusData();
        }
    }, 30000);
}

function loadStatusData() {
    const statusContainer = document.getElementById('status-container');
    const statusContent = document.getElementById('status-content');
    
    if (!statusContainer || !statusContent) return;

    statusContainer.classList.add('loading');
    
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                displayStatusData(statusContent, data.data);
            } else {
                throw new Error(data.error || 'Failed to load status');
            }
        })
        .catch(error => {
            statusContent.innerHTML = `
                <div class="error-message">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>Error Loading Status</h3>
                    <p>${error.message}</p>
                    <button class="btn primary" onclick="loadStatusData()">
                        <i class="fas fa-refresh"></i>
                        Retry
                    </button>
                </div>
            `;
        })
        .finally(() => {
            statusContainer.classList.remove('loading');
        });
}

function displayStatusData(container, data) {
    const html = `
        <div class="status-grid">
            <div class="status-card">
                <h3><i class="fas fa-info-circle"></i> Application Information</h3>
                <table>
                    <tr>
                        <th>Name:</th>
                        <td>${data.app.name}</td>
                    </tr>
                    <tr>
                        <th>Version:</th>
                        <td>${data.app.version}</td>
                    </tr>
                    <tr>
                        <th>Author:</th>
                        <td>${data.app.author}</td>
                    </tr>
                    <tr>
                        <th>Last Updated:</th>
                        <td>${new Date(data.timestamp).toLocaleString()}</td>
                    </tr>
                </table>
            </div>
            
            <div class="status-card">
                <h3><i class="fas fa-folder"></i> Workspace Status</h3>
                <table>
                    <tr>
                        <th>Source Directory:</th>
                        <td class="${data.workspace.src ? 'success' : 'error'}">
                            <i class="fas fa-${data.workspace.src ? 'check' : 'times'}"></i>
                            ${data.workspace.src ? 'Available' : 'Missing'}
                        </td>
                    </tr>
                    <tr>
                        <th>Resources Directory:</th>
                        <td class="${data.workspace.resources ? 'success' : 'error'}">
                            <i class="fas fa-${data.workspace.resources ? 'check' : 'times'}"></i>
                            ${data.workspace.resources ? 'Available' : 'Missing'}
                        </td>
                    </tr>
                    ${data.workspace.disk_space ? `
                    <tr>
                        <th>Disk Space:</th>
                        <td>
                            <div class="disk-space">
                                <div class="space-text">
                                    ${data.workspace.disk_space.used} / ${data.workspace.disk_space.total} used
                                    (${data.workspace.disk_space.percent}%)
                                </div>
                                <div class="progress-bar">
                                    <div class="progress ${data.workspace.disk_space.percent > 80 ? 'warning' : ''}" 
                                        style="width: ${data.workspace.disk_space.percent}%"></div>
                                </div>
                            </div>
                        </td>
                    </tr>
                    ` : ''}
                </table>
            </div>
            
            ${data.system ? `
            <div class="status-card">
                <h3><i class="fas fa-server"></i> System Resources</h3>
                <table>
                    <tr>
                        <th>CPU Usage:</th>
                        <td>
                            <div class="resource-indicator">
                                <div class="progress-bar">
                                    <div class="progress ${data.system.cpu_percent > 80 ? 'warning' : ''}" 
                                        style="width: ${data.system.cpu_percent}%"></div>
                                </div>
                                <span>${data.system.cpu_percent}%</span>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <th>Memory Usage:</th>
                        <td>
                            <div class="resource-indicator">
                                <div class="progress-bar">
                                    <div class="progress ${data.system.memory_percent > 80 ? 'warning' : ''}" 
                                        style="width: ${data.system.memory_percent}%"></div>
                                </div>
                                <span>${data.system.memory_percent}%</span>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
            ` : ''}
            
            <div class="status-card">
                <h3><i class="fas fa-tasks"></i> Job Statistics</h3>
                <table>
                    <tr>
                        <th>Total Jobs:</th>
                        <td>${data.jobs.total}</td>
                    </tr>
                    <tr>
                        <th>Running:</th>
                        <td class="warning">${data.jobs.running}</td>
                    </tr>
                    <tr>
                        <th>Completed:</th>
                        <td class="success">${data.jobs.completed}</td>
                    </tr>
                    <tr>
                        <th>Failed:</th>
                        <td class="error">${data.jobs.failed}</td>
                    </tr>
                </table>
            </div>
            
            <div class="status-card">
                <h3><i class="fas fa-clock"></i> Latest Output</h3>
                ${data.latest_output ? 
                    `<p><code>${data.latest_output}</code></p>` : 
                    '<p class="text-muted">No recent analysis outputs found.</p>'
                }
            </div>
        </div>
    `;
    
    container.innerHTML = html;
}

function refreshStatus() {
    loadStatusData();
    showNotification('Status refreshed', 'success');
}

function initializeRecentJobs() {
    loadRecentJobs();
}

function loadRecentJobs() {
    const recentJobsList = document.getElementById('recent-jobs-list');
    if (!recentJobsList) return;
    
    fetch('/api/jobs?per_page=5')
        .then(response => response.json())
        .then(data => {
            if (data.success && data.data.jobs.length > 0) {
                displayRecentJobs(recentJobsList, data.data.jobs);
            } else {
                recentJobsList.innerHTML = '<p class="text-muted text-center">No recent jobs found</p>';
            }
        })
        .catch(error => {
            recentJobsList.innerHTML = '<p class="text-error text-center">Failed to load recent jobs</p>';
        });
}

function displayRecentJobs(container, jobs) {
    const html = jobs.map(job => `
        <div class="job-card ${job.status}">
            <div class="job-header">
                <h4><a href="/job/${job.id}">${job.id.substring(0, 8)}...</a></h4>
                <span class="status-badge ${job.status}">${job.status}</span>
            </div>
            <div class="job-details">
                <p><strong>Type:</strong> ${job.type}</p>
                <p><strong>Created:</strong> ${formatDateTime(job.created_at)}</p>
                ${job.type === 'single' ? 
                    `<p><strong>File:</strong> ${job.filename}</p>` :
                    `<p><strong>Files:</strong> ${job.file_count}</p>`
                }
            </div>
            ${job.status === 'running' ? `
                <div class="progress-bar">
                    <div class="progress" style="width: ${job.progress}%"></div>
                </div>
                <div class="progress-text">${job.progress}% Complete</div>
            ` : ''}
        </div>
    `).join('');
    
    container.innerHTML = html;
}

function initializeFormValidation() {
    const forms = document.querySelectorAll('.analysis-form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(form)) {
                e.preventDefault();
                return false;
            }

            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
                submitBtn.disabled = true;
            }
            
            showLoadingOverlay('Starting Analysis...', 'Please wait while we begin processing your request');
        });
    });
}

function validateForm(form) {
    const fileInputs = form.querySelectorAll('input[type="file"]');
    let isValid = true;
    
    fileInputs.forEach(input => {
        if (input.required && input.files.length === 0) {
            showNotification('Please select at least one APK file', 'error');
            isValid = false;
        }
    });
    
    return isValid;
}

function initializeActionCards() {
    const actionCards = document.querySelectorAll('.action-card');
    
    actionCards.forEach(card => {
        card.addEventListener('click', function() {
            const tabId = card.getAttribute('data-tab');
            if (tabId) {
                switchToTab(tabId);
            }
        });
    });
}

function validateApkFile(file) {
    if (!file.name.toLowerCase().endsWith('.apk')) {
        showNotification(`${file.name} is not a valid APK file`, 'error');
        return false;
    }

    if (file.size > 500 * 1024 * 1024) {
        showNotification(`${file.name} is too large (max 500MB)`, 'error');
        return false;
    }
    
    return true;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDateTime(timestamp) {
    if (!timestamp) return 'N/A';
    
    if (typeof timestamp === 'number') {
        return new Date(timestamp * 1000).toLocaleString();
    } else if (typeof timestamp === 'string') {
        return new Date(timestamp).toLocaleString();
    }
    
    return 'Invalid date';
}

function showNotification(message, type = 'info') {

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
            <button class="notification-close">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 5000);

    notification.querySelector('.notification-close').addEventListener('click', () => {
        notification.remove();
    });

    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
}

function getNotificationIcon(type) {
    switch(type) {
        case 'success': return 'check-circle';
        case 'error': return 'exclamation-circle';
        case 'warning': return 'exclamation-triangle';
        case 'info': 
        default: return 'info-circle';
    }
}

function showLoadingOverlay(title, message) {
    const overlay = document.getElementById('loading-overlay');
    if (!overlay) return;
    
    const titleElement = overlay.querySelector('h3');
    const messageElement = overlay.querySelector('#loading-message');
    
    if (titleElement) titleElement.textContent = title;
    if (messageElement) messageElement.textContent = message;
    
    overlay.style.display = 'flex';
}

function hideLoadingOverlay() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) overlay.style.display = 'none';
}

window.cancelJob = function(jobId) {
    if (!confirm('Are you sure you want to cancel this job?')) return;
    
    fetch(`/api/job/${jobId}/cancel`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': AppState.csrfToken
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Job cancelled successfully', 'success');
            location.reload();
        } else {
            showNotification(data.error || 'Failed to cancel job', 'error');
        }
    })
    .catch(error => {
        showNotification('Failed to cancel job', 'error');
    });
};

window.deleteJob = function(jobId) {
    if (!confirm('Are you sure you want to delete this job? This action cannot be undone.')) return;
    
    fetch(`/api/job/${jobId}/delete`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': AppState.csrfToken
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Job deleted successfully', 'success');
            location.reload();
        } else {
            showNotification(data.error || 'Failed to delete job', 'error');
        }
    })
    .catch(error => {
        showNotification('Failed to delete job', 'error');
    });
};

window.refreshStatus = refreshStatus;
window.removeFromQueue = function(index) {
    AppState.uploadQueue.splice(index, 1);
    updateQueueDisplay();
};
window.clearQueue = function() {
    AppState.uploadQueue = [];
    updateQueueDisplay();
    showNotification('Queue cleared', 'info');
};
window.processQueue = function() {
    if (AppState.uploadQueue.length === 0) {
        showNotification('No files in queue', 'warning');
        return;
    }

    const dt = new DataTransfer();
    AppState.uploadQueue.forEach(file => dt.items.add(file));

    const form = document.createElement('form');
    form.action = '/batch';
    form.method = 'post';
    form.enctype = 'multipart/form-data';
    form.style.display = 'none';

    if (AppState.csrfToken) {
        const csrfInput = document.createElement('input');
        csrfInput.type = 'hidden';
        csrfInput.name = 'csrf_token';
        csrfInput.value = AppState.csrfToken;
        form.appendChild(csrfInput);
    }

    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.name = 'apk_files';
    fileInput.multiple = true;
    fileInput.files = dt.files;
    form.appendChild(fileInput);

    const engineInput = document.createElement('input');
    engineInput.type = 'hidden';
    engineInput.name = 'engine';
    engineInput.value = 'auto';
    form.appendChild(engineInput);
    
    document.body.appendChild(form);
    showLoadingOverlay('Processing queue...', 'Please wait while we start the batch analysis');
    form.submit();
};
window.clearBatchFiles = function() {
    const input = document.getElementById('apk_files');
    const filesList = document.getElementById('batch-files-list');
    
    if (input) input.value = '';
    if (filesList) {
        filesList.style.display = 'none';
        filesList.innerHTML = '';
    }
};
window.removeBatchFile = function(index) {
    const input = document.getElementById('apk_files');
    const files = Array.from(input.files);
    files.splice(index, 1);
    
    const dt = new DataTransfer();
    files.forEach(file => dt.items.add(file));
    input.files = dt.files;
    
    handleBatchFileSelect({ target: input });
};

const notificationStyles = `
.notification {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 1000;
    background: white;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    padding: 16px;
    min-width: 300px;
    transform: translateX(100%);
    transition: transform 0.3s ease-out;
}

.notification.show {
    transform: translateX(0);
}

.notification.success { border-left: 4px solid var(--success-color); }
.notification.error { border-left: 4px solid var(--error-color); }
.notification.warning { border-left: 4px solid var(--warning-color); }
.notification.info { border-left: 4px solid var(--info-color); }

.notification-content {
    display: flex;
    align-items: center;
    gap: 12px;
}

.notification-content i { font-size: 18px; }
.notification.success i { color: var(--success-color); }
.notification.error i { color: var(--error-color); }
.notification.warning i { color: var(--warning-color); }
.notification.info i { color: var(--info-color); }

.notification-close {
    background: none;
    border: none;
    cursor: pointer;
    margin-left: auto;
    color: #666;
}

.job-card {
    background: white;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 16px;
    transition: transform 0.2s ease-out;
}

.job-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.job-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
}

.job-header h4 { margin: 0; }
.job-header a { color: var(--primary-color); text-decoration: none; }

.status-badge {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}

.status-badge.running { background: var(--warning-color); color: white; }
.status-badge.completed { background: var(--success-color); color: white; }
.status-badge.failed, .status-badge.error { background: var(--error-color); color: white; }

.job-details p {
    margin: 4px 0;
    font-size: 14px;
    color: var(--text-secondary);
}

.file-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    margin-bottom: 8px;
    background: var(--surface-secondary);
}

.resource-indicator {
    display: flex;
    align-items: center;
    gap: 12px;
}

.resource-indicator .progress-bar { flex: 1; }

.error-message {
    text-align: center;
    padding: 32px;
    color: var(--text-secondary);
}

.error-message i {
    font-size: 48px;
    color: var(--error-color);
    margin-bottom: 16px;
}

.error-message h3 {
    margin-bottom: 8px;
    color: var(--text-primary);
}
`;

const style = document.createElement('style');
style.textContent = notificationStyles;
document.head.appendChild(style);
