
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

    const navbar = document.querySelector('.navbar') || document.querySelector('.nav-glass') || document.querySelector('nav');
    
    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function(e) {
            e.stopPropagation();
            navMenu.classList.toggle('active');
            navToggle.classList.toggle('active');

            if (navMenu.classList.contains('active')) {
                document.body.style.overflow = 'hidden';
            } else {
                document.body.style.overflow = '';
            }
        });
    }

    document.addEventListener('click', function(e) {
        if (!e.target.closest('.nav-container') || e.target.closest('.nav-link')) {
            if (navMenu) {
                navMenu.classList.remove('active');
                document.body.style.overflow = '';
            }
            if (navToggle) navToggle.classList.remove('active');
        }
    });

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && navMenu && navMenu.classList.contains('active')) {
            navMenu.classList.remove('active');
            navToggle.classList.remove('active');
            document.body.style.overflow = '';
        }
    });

    let lastScrollTop = 0;
    window.addEventListener('scroll', function() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        if (navbar) {
            if (scrollTop > 10) {
                navbar.classList.add('scrolled');
            } else {
                navbar.classList.remove('scrolled');
            }
        }
        
        lastScrollTop = scrollTop;
    }, { passive: true });
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
    fileInfo.classList.remove('is-hidden');

        const removeBtn = fileInfo.querySelector('.remove-file');
        if (removeBtn) {
            removeBtn.onclick = () => {
                e.target.value = '';
        fileInfo.classList.add('is-hidden');
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
    filesList.classList.remove('is-hidden');
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
        uploadQueue.classList.add('is-hidden');
        return;
    }
    
    uploadQueue.classList.remove('is-hidden');
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

    if (title === 'Starting Analysis...' || title.includes('Analysis')) {
        const progressContainer = document.getElementById('analysis-progress-container');
        const analysisList = document.getElementById('analysis-steps');
        
        if (progressContainer) {
            progressContainer.classList.remove('is-hidden');
            progressContainer.style.display = 'block';

            const progressBar = document.getElementById('analysis-progress-bar');
            const progressPercentage = document.getElementById('progress-percentage');
            if (progressBar) {
                progressBar.style.width = '0%';
                progressBar.className = 'progress-bar progress-initial';
            }
            if (progressPercentage) progressPercentage.textContent = '0%';

            if (analysisList) analysisList.innerHTML = '';

            const steps = [
                { text: 'Initializing analysis environment...', icon: 'fas fa-play', status: 'pending' },
                { text: 'Extracting and parsing APK contents...', icon: 'fas fa-file-archive', status: 'pending' },
                { text: 'Performing static code analysis...', icon: 'fas fa-code', status: 'pending' },
                { text: 'Analyzing permissions and manifest...', icon: 'fas fa-shield-alt', status: 'pending' },
                { text: 'Running dynamic analysis...', icon: 'fas fa-cogs', status: 'pending' },
                { text: 'Scanning for security vulnerabilities...', icon: 'fas fa-bug', status: 'pending' },
                { text: 'Analyzing network behavior...', icon: 'fas fa-network-wired', status: 'pending' },
                { text: 'Generating comprehensive report...', icon: 'fas fa-file-contract', status: 'pending' }
            ];
            
            steps.forEach((step, index) => {
                const li = document.createElement('li');
                li.className = 'analysis-step';
                li.dataset.stepIndex = index;
                li.innerHTML = `
                    <i class="${step.icon} step-icon"></i>
                    <span class="step-text">${step.text}</span>
                    <i class="fas fa-spinner fa-spin step-spinner" style="display: none;"></i>
                    <i class="fas fa-check step-check" style="display: none;"></i>
                `;
                analysisList.appendChild(li);
            });

            simulateAnalysisProgress();
        }
    }
    
    overlay.classList.remove('is-hidden');
}

function hideLoadingOverlay() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) overlay.classList.add('is-hidden');

    const progressContainer = document.getElementById('analysis-progress-container');
    if (progressContainer) {
        progressContainer.style.display = 'none';
        progressContainer.classList.add('is-hidden');
    }
}

function simulateAnalysisProgress() {
    const progressBar = document.getElementById('analysis-progress-bar');
    const progressPercentage = document.getElementById('progress-percentage');
    const analysisList = document.getElementById('analysis-steps');
    
    if (!progressBar || !progressPercentage || !analysisList) return;
    
    const listItems = analysisList.querySelectorAll('.analysis-step');
    let currentStep = 0;
    let progress = 0;
    let stepStartTime = Date.now();

    const progressStages = [
        { minProgress: 0, maxProgress: 10, step: 0, duration: 2000 },
        { minProgress: 10, maxProgress: 25, step: 1, duration: 3000 },
        { minProgress: 25, maxProgress: 45, step: 2, duration: 4000 },
        { minProgress: 45, maxProgress: 60, step: 3, duration: 2500 },
        { minProgress: 60, maxProgress: 75, step: 4, duration: 5000 },
        { minProgress: 75, maxProgress: 85, step: 5, duration: 3000 },
        { minProgress: 85, maxProgress: 95, step: 6, duration: 2000 },
        { minProgress: 95, maxProgress: 99, step: 7, duration: 1500 }
    ];
    
    let currentStageIndex = 0;

    const interval = setInterval(() => {

        const overlay = document.getElementById('loading-overlay');
        if (overlay && overlay.classList.contains('is-hidden')) {
            clearInterval(interval);
            return;
        }
        
        const currentStage = progressStages[currentStageIndex];
        if (!currentStage) {
            clearInterval(interval);
            return;
        }
        
        const stageElapsed = Date.now() - stepStartTime;
        const stageProgress = Math.min(stageElapsed / currentStage.duration, 1);

        const stageProgressRange = currentStage.maxProgress - currentStage.minProgress;
        progress = currentStage.minProgress + (stageProgress * stageProgressRange);

        progressBar.style.width = progress + '%';
        progressPercentage.textContent = Math.round(progress) + '%';

        progressBar.className = 'progress-bar';
        if (progress < 30) {
            progressBar.classList.add('progress-warning');
        } else if (progress < 70) {
            progressBar.classList.add('progress-info');
        } else if (progress < 95) {
            progressBar.classList.add('progress-primary');
        } else {
            progressBar.classList.add('progress-success');
        }

        if (currentStage.step !== currentStep) {

            for (let i = 0; i < currentStage.step; i++) {
                const step = listItems[i];
                if (step) {
                    step.classList.add('completed');
                    step.classList.remove('in-progress');
                    step.querySelector('.step-spinner').style.display = 'none';
                    step.querySelector('.step-check').style.display = 'inline';
                    step.querySelector('.step-icon').style.opacity = '0.6';
                }
            }

            const currentStepElement = listItems[currentStage.step];
            if (currentStepElement) {
                currentStepElement.classList.add('in-progress');
                currentStepElement.classList.remove('completed');
                currentStepElement.querySelector('.step-spinner').style.display = 'inline';
                currentStepElement.querySelector('.step-check').style.display = 'none';
                currentStepElement.querySelector('.step-icon').style.opacity = '1';
            }
            
            currentStep = currentStage.step;
        }

        if (stageProgress >= 1 && currentStageIndex < progressStages.length - 1) {

            const stepElement = listItems[currentStage.step];
            if (stepElement) {
                stepElement.classList.add('completed');
                stepElement.classList.remove('in-progress');
                stepElement.querySelector('.step-spinner').style.display = 'none';
                stepElement.querySelector('.step-check').style.display = 'inline';
            }
            
            currentStageIndex++;
            stepStartTime = Date.now();
        }

        if (progress >= 99) {
            clearInterval(interval);
            setTimeout(() => {

                const form = document.querySelector('form[action="/analyze"], form[action="/batch"]');
                if (form && form.dataset.submitted === 'true') {
                    hideLoadingOverlay();
                }
            }, 1000);
        }
        
    }, 500); // Update every 500ms for smooth animation

    window.analysisProgressInterval = interval;
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
    form.classList.add('is-hidden');

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
    filesList.classList.add('is-hidden');
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
    border-radius: var(--radius-md);
    margin-bottom: 8px;
    background: var(--surface-color);
    transition: all var(--transition-normal);
}

.file-item:hover {
    transform: translateY(-1px);
    box-shadow: var(--shadow-sm);
    border-color: var(--accent-color);
}

.file-item .file-name {
    font-weight: 600;
    color: var(--text-primary);
}

.file-item .file-size {
    font-size: 0.875rem;
    color: var(--text-muted);
}

.file-item .remove-file {
    background: var(--error-color);
    color: white;
    border: none;
    border-radius: var(--radius-full);
    width: 28px;
    height: 28px;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all var(--transition-normal);
}

.file-item .remove-file:hover {
    background: #b91c1c;
    transform: scale(1.1);
}
`

class NotificationManager {
    constructor() {
        this.container = this.createContainer();
        this.notifications = new Map();
        this.defaultDuration = 5000;
    }
    
    createContainer() {
        let container = document.getElementById('notification-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'notification-container';
            container.className = 'notification-container';
            document.body.appendChild(container);
        }
        return container;
    }
    
    show(message, type = 'info', duration = this.defaultDuration, actions = []) {
        const id = 'notification-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        const notification = this.createNotification(id, message, type, actions);
        
        this.container.appendChild(notification);
        this.notifications.set(id, notification);

        requestAnimationFrame(() => {
            notification.classList.add('show');
        });

        if (duration > 0) {
            setTimeout(() => this.dismiss(id), duration);
        }
        
        return id;
    }
    
    createNotification(id, message, type, actions) {
        const notification = document.createElement('div');
        notification.className = 'notification notification-' + type;
        notification.setAttribute('data-id', id);
        
        const icon = this.getTypeIcon(type);
        
        notification.innerHTML = 
            '<div class="notification-content">' +
                '<div class="notification-icon">' +
                    '<i class="' + icon + '"></i>' +
                '</div>' +
                '<div class="notification-message">' + message + '</div>' +
                '<button class="notification-close" onclick="notificationManager.dismiss(\'' + id + '\')">' +
                    '<i class="fas fa-times"></i>' +
                '</button>' +
            '</div>' +
            (actions.length > 0 ? 
                '<div class="notification-actions">' +
                    actions.map(action => 
                        '<button class="notification-action btn small ' + (action.style || 'ghost') + '" ' +
                                'onclick="' + action.onclick + '; notificationManager.dismiss(\'' + id + '\')">' +
                            action.text +
                        '</button>'
                    ).join('') +
                '</div>'
            : '');
        
        return notification;
    }
    
    getTypeIcon(type) {
        const icons = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle', 
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle',
            loading: 'fas fa-spinner fa-spin'
        };
        return icons[type] || icons.info;
    }
    
    dismiss(id) {
        const notification = this.notifications.get(id);
        if (notification) {
            notification.classList.add('hide');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
                this.notifications.delete(id);
            }, 300);
        }
    }
    
    clear() {
        this.notifications.forEach((notification, id) => {
            this.dismiss(id);
        });
    }

    success(message, duration, actions) {
        return this.show(message, 'success', duration, actions);
    }
    
    error(message, duration, actions) {
        return this.show(message, 'error', duration, actions);
    }
    
    warning(message, duration, actions) {
        return this.show(message, 'warning', duration, actions);
    }
    
    info(message, duration, actions) {
        return this.show(message, 'info', duration, actions);
    }
    
    loading(message) {
        return this.show(message, 'loading', 0);
    }
}

const notificationManager = new NotificationManager();

const UIUtils = {

    scrollTo(element, offset = 0) {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        
        if (element) {
            const top = element.offsetTop - offset;
            window.scrollTo({
                top: top,
                behavior: 'smooth'
            });
        }
    },

    setLoading(element, isLoading) {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        
        if (element) {
            if (isLoading) {
                element.classList.add('loading');
                element.disabled = true;
            } else {
                element.classList.remove('loading');
                element.disabled = false;
            }
        }
    },

    validateForm(form) {
        if (typeof form === 'string') {
            form = document.querySelector(form);
        }
        
        const errors = [];
        const inputs = form.querySelectorAll('[required]');
        
        inputs.forEach(input => {
            if (!input.value.trim()) {
                errors.push((input.name || input.id) + ' is required');
                input.classList.add('error');
            } else {
                input.classList.remove('error');
            }
        });
        
        return {
            isValid: errors.length === 0,
            errors: errors
        };
    },

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    formatDuration(seconds) {
        if (seconds < 60) return Math.round(seconds) + 's';
        if (seconds < 3600) return Math.round(seconds / 60) + 'm';
        return Math.round(seconds / 3600) + 'h';
    },

    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            notificationManager.success('Copied to clipboard!', 2000);
            return true;
        } catch (err) {
            notificationManager.error('Failed to copy to clipboard', 3000);
            return false;
        }
    },

    downloadFile(content, filename, type = 'text/plain') {
        const blob = new Blob([content], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
};

function showNotification(message, type = 'info', duration = 5000) {
    return notificationManager.show(message, type, duration);
}

window.addEventListener('error', function(event) {
    console.error('JavaScript error:', event.error);
    notificationManager.error('An unexpected error occurred. Please refresh the page if issues persist.', 8000);
});

window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    notificationManager.error('A network or processing error occurred.', 5000);
});

const perfMonitor = {
    marks: new Map(),
    
    start(name) {
        this.marks.set(name, performance.now());
    },
    
    end(name) {
        const start = this.marks.get(name);
        if (start) {
            const duration = performance.now() - start;
            console.log('Performance [' + name + ']: ' + duration.toFixed(2) + 'ms');
            this.marks.delete(name);
            return duration;
        }
        return null;
    }
};

document.addEventListener('DOMContentLoaded', function() {

    if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animated');
                }
            });
        }, {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        });

        document.querySelectorAll('.action-card, .stat-item, .form-group').forEach(el => {
            observer.observe(el);
        });
    }

    document.addEventListener('keydown', function(e) {

        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.querySelector('#search-input');
            if (searchInput) {
                searchInput.focus();
            }
        }

        if (e.key === 'Escape') {
            const overlay = document.querySelector('#loading-overlay:not(.is-hidden)');
            if (overlay && !overlay.querySelector('.loading')) {
                overlay.classList.add('is-hidden');
            }
        }
    });
    
    console.log('Enhanced UI features initialized');
});

const style = document.createElement('style');
style.textContent = notificationStyles;
document.head.appendChild(style);
