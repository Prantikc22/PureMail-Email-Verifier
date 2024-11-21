// Drag and drop functionality
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('emailFile');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const verifyBtn = document.getElementById('verifyBtn');
const progressContainer = document.getElementById('progressContainer');
const progressBar = document.getElementById('progressBar');
const progressText = document.getElementById('progressText');
const results = document.getElementById('results');
const downloadBtn = document.getElementById('downloadBtn');
const message = document.getElementById('message');

function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.add('drag-over');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drag-over');
}

function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    dropZone.classList.remove('drag-over');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFile(files[0]);
    }
}

function handleFile(file) {
    const validTypes = ['.csv', '.txt', '.xlsx', '.xls'];
    const extension = '.' + file.name.split('.').pop().toLowerCase();
    
    if (!validTypes.includes(extension)) {
        showMessage('Please upload a valid file type (.csv, .txt, .xlsx, .xls)', 'error');
        return;
    }
    
    fileName.textContent = file.name;
    fileInfo.style.display = 'block';
    
    // Create a new DataTransfer object and add the file
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    fileInput.files = dataTransfer.files;
}

function showMessage(text, type = 'info') {
    message.textContent = text;
    message.className = `alert alert-${type} mt-4`;
    message.style.display = 'block';
    setTimeout(() => {
        message.style.display = 'none';
    }, 5000);
}

function updateResults(data) {
    document.getElementById('results').style.display = 'block';
    document.getElementById('validEmails').textContent = data.valid_emails;
    document.getElementById('invalidFormat').textContent = data.invalid_format;
    document.getElementById('disposable').textContent = data.disposable;
    document.getElementById('dnsErrors').textContent = data.dns_error;
    document.getElementById('roleBased').textContent = data.role_based;
    
    // Update AI scores
    document.getElementById('replyScore').textContent = data.reply_score ? data.reply_score + '/10' : 'N/A';
    document.getElementById('realPersonScore').textContent = data.real_person_score ? data.real_person_score + '/10' : 'N/A';
    document.getElementById('engagementScore').textContent = data.engagement_score ? data.engagement_score + '/10' : 'N/A';
    
    // Show download button with verification ID
    const downloadBtn = document.getElementById('downloadBtn');
    downloadBtn.style.display = 'inline-block';
    downloadBtn.setAttribute('data-verification-id', data.verification_id);
}

// Event listeners
dropZone.addEventListener('dragover', handleDragOver);
dropZone.addEventListener('dragleave', handleDragLeave);
dropZone.addEventListener('drop', handleDrop);
dropZone.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
});

verifyBtn.addEventListener('click', () => {
    const file = fileInput.files[0];
    if (!file) {
        showMessage('Please select a file first', 'error');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    progressContainer.style.display = 'block';
    verifyBtn.disabled = true;
    progressBar.style.width = '0%';
    progressBar.textContent = '0%';
    results.style.display = 'none';
    downloadBtn.style.display = 'none';
    
    fetch('/verify', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            throw new Error(data.error);
        }
        
        progressBar.style.width = '100%';
        progressBar.textContent = '100%';
        updateResults(data);
        showMessage('Verification completed successfully!', 'success');
    })
    .catch(error => {
        console.error('Verification error:', error);
        showMessage(error.message || 'An error occurred during verification', 'error');
        results.style.display = 'none';
        downloadBtn.style.display = 'none';
    })
    .finally(() => {
        progressContainer.style.display = 'none';
        verifyBtn.disabled = false;
    });
});
