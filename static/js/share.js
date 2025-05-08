// Facebook Auto Share - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const shareForm = document.getElementById('shareForm');
    const startSharingBtn = document.getElementById('startSharingBtn');
    const progressSection = document.getElementById('progressSection');
    const noProgressSection = document.getElementById('noProgressSection');
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const shareStatus = document.getElementById('shareStatus');
    
    // Variables
    let currentTaskId = null;
    let statusCheckInterval = null;
    
    // Event Listeners
    shareForm.addEventListener('submit', handleSubmit);
    
    // Functions
    function handleSubmit(e) {
        e.preventDefault();
        
        // Get form data
        const postUrl = document.getElementById('postUrl').value;
        const cookieJson = document.getElementById('cookieJson').value;
        const shareCount = parseInt(document.getElementById('shareCount').value);
        const delaySeconds = parseInt(document.getElementById('delaySeconds').value);
        
        // Validate cookie JSON
        let cookieData;
        try {
            cookieData = JSON.parse(cookieJson);
            if (!Array.isArray(cookieData)) {
                throw new Error('Cookie data must be an array');
            }
        } catch (error) {
            showAlert('Invalid Cookie Format', 'Please provide a valid JSON array of cookies. Use the Cookie Getter tool if needed.');
            return;
        }
        
        // Disable form and show progress
        startSharingBtn.disabled = true;
        startSharingBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Starting...';
        
        // Send request to start sharing
        fetch('/api/start_sharing', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                post_url: postUrl,
                cookie: cookieData,
                share_count: shareCount,
                delay: delaySeconds
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Show progress section
                progressSection.style.display = 'block';
                noProgressSection.style.display = 'none';
                
                // Update UI
                shareStatus.innerHTML = '<div class="message-info">Task started successfully!</div>';
                progressBar.style.width = '0%';
                progressBar.textContent = '0%';
                progressText.textContent = `0/${shareCount} shares completed`;
                
                // Store task ID and start checking status
                currentTaskId = data.task_id;
                if (statusCheckInterval) {
                    clearInterval(statusCheckInterval);
                }
                statusCheckInterval = setInterval(checkShareStatus, 1000);
                
                // Reset form button
                startSharingBtn.disabled = false;
                startSharingBtn.innerHTML = '<i class="fas fa-play me-2"></i>Start Sharing';
            } else {
                // Show error
                showAlert('Error', data.error || 'Failed to start sharing task');
                
                // Reset form button
                startSharingBtn.disabled = false;
                startSharingBtn.innerHTML = '<i class="fas fa-play me-2"></i>Start Sharing';
            }
        })
        .catch(error => {
            // Show error
            showAlert('Error', 'Network error: ' + error.message);
            
            // Reset form button
            startSharingBtn.disabled = false;
            startSharingBtn.innerHTML = '<i class="fas fa-play me-2"></i>Start Sharing';
        });
    }
    
    function checkShareStatus() {
        if (!currentTaskId) return;
        
        fetch(`/api/check_share_status/${currentTaskId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const result = data.result;
                    
                    // Update progress bar
                    const total = result.total || 1; // Avoid division by zero
                    const current = result.current || 0;
                    const percentage = Math.round((current / total) * 100);
                    
                    progressBar.style.width = `${percentage}%`;
                    progressBar.textContent = `${percentage}%`;
                    progressText.textContent = `${current}/${total} shares completed`;
                    
                    // Update status messages
                    updateStatusMessages(result.messages);
                    
                    // Check if completed
                    if (result.completed) {
                        clearInterval(statusCheckInterval);
                        
                        // Update UI based on final status
                        if (result.status === 'completed') {
                            progressBar.classList.remove('bg-danger');
                            progressBar.classList.add('bg-success');
                        } else if (result.status === 'failed') {
                            progressBar.classList.remove('bg-success');
                            progressBar.classList.add('bg-danger');
                        }
                    }
                } else {
                    // Task not found or error
                    clearInterval(statusCheckInterval);
                    shareStatus.innerHTML += `<div class="message-error">Error checking status: ${data.error}</div>`;
                }
            })
            .catch(error => {
                // Network error
                shareStatus.innerHTML += `<div class="message-error">Network error: ${error.message}</div>`;
            });
    }
    
    function updateStatusMessages(messages) {
        if (!messages || !Array.isArray(messages)) return;
        
        // Clear existing messages
        shareStatus.innerHTML = '';
        
        // Add all messages
        messages.forEach(msg => {
            const messageClass = `message-${msg.type}`;
            shareStatus.innerHTML += `<div class="${messageClass}">${msg.message}</div>`;
        });
        
        // Scroll to bottom
        shareStatus.scrollTop = shareStatus.scrollHeight;
    }
    
    function showAlert(title, message) {
        // Create Bootstrap alert
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger alert-dismissible fade show';
        alertDiv.role = 'alert';
        alertDiv.innerHTML = `
            <strong>${title}:</strong> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Insert at the top of the form
        shareForm.parentNode.insertBefore(alertDiv, shareForm);
        
        // Auto remove after 10 seconds
        setTimeout(() => {
            alertDiv.remove();
        }, 10000);
    }
});
