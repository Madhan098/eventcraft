/**
 * Emotional Features JavaScript
 * Personal Messages, Memories, Countdown, Voice Message
 */

// ========== PERSONAL MESSAGE ==========
async function loadPersonalMessage(shareUrl, guestEmail, guestName) {
    try {
        const response = await fetch(
            `/api/invitations/${shareUrl}/personal-message?guestEmail=${encodeURIComponent(guestEmail)}&guestName=${encodeURIComponent(guestName || '')}`
        );
        const data = await response.json();
        
        if (data.success && data.message) {
            displayPersonalMessage(data.message, data.guestName);
            return true;
        }
        return false;
    } catch (error) {
        console.error('Error loading personal message:', error);
        return false;
    }
}

function displayPersonalMessage(message, guestName) {
    const container = document.getElementById('personal-message-container');
    if (!container) return;
    
    // Parse the message (format: "Name,\n\nOpening Impact\n\nClosing")
    const lines = message.split('\n').filter(line => line.trim());
    const nameLine = lines[0] || guestName;
    const openingImpact = lines[1] || '';
    const closing = lines[2] || '';
    
    container.innerHTML = `
        <div class="personal-message-content">
            <p class="guest-name">${nameLine}</p>
            <p class="message-line-1">${openingImpact}</p>
            <p class="message-line-3">${closing}</p>
        </div>
        <div class="divider"></div>
    `;
    container.style.display = 'block';
}

// ========== COUNTDOWN TIMER ==========
function initCountdownTimer(eventDate, showMystery = false) {
    const countdownContainer = document.getElementById('countdown-section');
    
    // Debug logging
    console.log('🕐 Initializing countdown timer...');
    console.log('📅 Event Date:', eventDate);
    console.log('📦 Container found:', !!countdownContainer);
    
    if (!countdownContainer) {
        console.error('❌ Countdown container not found!');
        return;
    }
    
    if (!eventDate || eventDate === '' || eventDate === 'None') {
        console.error('❌ Event date is missing or invalid:', eventDate);
        return;
    }
    
    let revealed = !showMystery;
    
    function calculateTimeLeft() {
        // Parse date - handle both ISO format and other formats
        let targetDate;
        
        try {
            // Try parsing as ISO string first
            if (typeof eventDate === 'string' && eventDate.includes('T')) {
                targetDate = new Date(eventDate);
            } else if (typeof eventDate === 'string') {
                // Try parsing as date string
                targetDate = new Date(eventDate);
            } else {
                targetDate = new Date(eventDate);
            }
            
            // Check if date is valid
            if (isNaN(targetDate.getTime())) {
                console.error('❌ Invalid date format:', eventDate);
                return { days: 0, hours: 0, minutes: 0, seconds: 0 };
            }
            
            const now = new Date().getTime();
            const targetTime = targetDate.getTime();
            const difference = targetTime - now;
            
            console.log('⏰ Target date:', targetDate);
            console.log('⏰ Current time:', new Date(now));
            console.log('⏰ Difference (ms):', difference);
            
            if (difference > 0) {
                const days = Math.floor(difference / (1000 * 60 * 60 * 24));
                const hours = Math.floor((difference % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                const minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((difference % (1000 * 60)) / 1000);
                
                return { days, hours, minutes, seconds };
            }
            
            // Event has passed
            console.log('⚠️ Event date has passed');
            return { days: 0, hours: 0, minutes: 0, seconds: 0 };
        } catch (error) {
            console.error('❌ Error calculating time left:', error);
            return { days: 0, hours: 0, minutes: 0, seconds: 0 };
        }
    }
    
    function updateCountdown() {
        const timeLeft = calculateTimeLeft();
        
        const daysEl = document.getElementById('countdown-days');
        const hoursEl = document.getElementById('countdown-hours');
        const minutesEl = document.getElementById('countdown-minutes');
        const secondsEl = document.getElementById('countdown-seconds');
        
        if (daysEl) {
            daysEl.textContent = String(timeLeft.days).padStart(2, '0');
        } else {
            console.warn('⚠️ Days element not found');
        }
        
        if (hoursEl) {
            hoursEl.textContent = String(timeLeft.hours).padStart(2, '0');
        } else {
            console.warn('⚠️ Hours element not found');
        }
        
        if (minutesEl) {
            minutesEl.textContent = String(timeLeft.minutes).padStart(2, '0');
        } else {
            console.warn('⚠️ Minutes element not found');
        }
        
        if (secondsEl) {
            secondsEl.textContent = String(timeLeft.seconds).padStart(2, '0');
        } else {
            console.warn('⚠️ Seconds element not found');
        }
    }
    
    // Initial update
    updateCountdown();
    
    // Update every second
    const countdownInterval = setInterval(updateCountdown, 1000);
    
    // Store interval ID for potential cleanup
    if (countdownContainer) {
        countdownContainer.dataset.countdownInterval = countdownInterval;
    }
    
    // Mystery mode reveal button
    if (showMystery && !revealed) {
        const revealBtn = document.getElementById('countdown-reveal-btn');
        if (revealBtn) {
            revealBtn.addEventListener('click', () => {
                revealed = true;
                const mysteryOverlay = document.getElementById('countdown-mystery-overlay');
                const eventDetails = document.getElementById('countdown-event-details');
                if (mysteryOverlay) mysteryOverlay.style.display = 'none';
                if (eventDetails) eventDetails.style.display = 'block';
                if (revealBtn) revealBtn.style.display = 'none';
            });
        }
    }
}

// ========== MEMORIES SECTION ==========
let memories = [];

async function loadMemories(shareUrl) {
    try {
        const response = await fetch(`/api/invitations/${shareUrl}/memories`);
        const data = await response.json();
        
        if (data.success) {
            memories = data.memories || [];
            displayMemories();
        }
    } catch (error) {
        console.error('Error loading memories:', error);
    }
}

function displayMemories() {
    const gallery = document.getElementById('memories-gallery');
    if (!gallery) return;
    
    const countEl = document.getElementById('memories-count');
    if (countEl) {
        countEl.textContent = `${memories.length} ${memories.length === 1 ? 'Memory' : 'Memories'} Shared`;
    }
    
    const grid = document.getElementById('memories-grid');
    if (!grid) return;
    
    if (memories.length === 0) {
        grid.innerHTML = `
            <div class="no-memories-yet">
                <p>No memories shared yet. Be the first!</p>
            </div>
        `;
        return;
    }
    
    grid.innerHTML = memories.map(memory => {
        const photoUrl = memory.photoUrl || memory.photo_url;
        const guestName = memory.guestName || memory.guest_name;
        const memoryText = memory.memoryText || memory.memory_text;
        const uploadedAt = memory.uploadedAt || memory.uploaded_at;
        
        return `
        <div class="memory-card">
            <div class="memory-image-wrapper">
                <img src="${photoUrl}" alt="Memory by ${guestName}" class="memory-image" onerror="this.src='/static/images/placeholder.jpg';">
            </div>
            <div class="memory-content">
                <p class="memory-label">A memory with you</p>
                <p class="memory-text">"${memoryText}"</p>
                <div class="memory-footer">
                    <span class="memory-author">— ${guestName}</span>
                    <span class="memory-date">${formatTimeAgo(uploadedAt)}</span>
                </div>
            </div>
        </div>
    `;
    }).join('');
    
    // Add scroll indicators if there are multiple memories
    if (memories.length > 1) {
        // Remove existing hint if any
        const existingHint = gallery.querySelector('.memories-scroll-hint');
        if (existingHint) {
            existingHint.remove();
        }
        
        const scrollHint = document.createElement('div');
        scrollHint.className = 'memories-scroll-hint';
        scrollHint.innerHTML = '<p style="text-align: center; color: #718096; margin-top: 10px; font-size: 0.9rem;">← Scroll to see more memories →</p>';
        gallery.appendChild(scrollHint);
    } else {
        // Remove hint if only one or no memories
        const existingHint = gallery.querySelector('.memories-scroll-hint');
        if (existingHint) {
            existingHint.remove();
        }
    }
}

function formatTimeAgo(dateString) {
    if (!dateString) return '';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
}

function initMemoryUpload(shareUrl, hostName) {
    const uploadForm = document.getElementById('memory-upload-form');
    if (!uploadForm) return;
    
    const photoInput = document.getElementById('memory-photo');
    const previewImage = document.getElementById('memory-preview');
    const memoryText = document.getElementById('memory-text');
    const uploaderName = document.getElementById('uploader-name');
    const submitBtn = document.getElementById('submit-memory-btn');
    
    // Ensure submit button is visible
    if (submitBtn) {
        submitBtn.style.display = 'block';
        submitBtn.style.visibility = 'visible';
        submitBtn.style.opacity = '1';
    }
    
    // Photo preview
    if (photoInput) {
        photoInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file && previewImage) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    previewImage.src = event.target.result;
                    previewImage.style.display = 'block';
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    // Submit memory
    if (uploadForm) {
        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (!photoInput.files[0] || !memoryText.value.trim() || !uploaderName.value.trim()) {
                alert('Please fill in all required fields');
                return;
            }
            
            const formData = new FormData();
            formData.append('photo', photoInput.files[0]);
            formData.append('memoryText', memoryText.value.trim());
            formData.append('guestName', uploaderName.value.trim());
            // Email is optional - not required
            formData.append('guestEmail', '');
            
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Uploading...';
            }
            
            try {
                console.log('📤 Uploading memory to:', `/api/invitations/${shareUrl}/memories`);
                console.log('📋 Form data:', {
                    hasPhoto: !!photoInput.files[0],
                    photoName: photoInput.files[0]?.name,
                    memoryText: memoryText.value.trim().substring(0, 50) + '...',
                    guestName: uploaderName.value.trim()
                });
                
                const response = await fetch(`/api/invitations/${shareUrl}/memories`, {
                    method: 'POST',
                    body: formData
                });
                
                console.log('📥 Response status:', response.status, response.statusText);
                console.log('📥 Response headers:', response.headers.get('content-type'));
                
                // Check if response is JSON
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    const text = await response.text();
                    console.error('❌ Non-JSON response:', text.substring(0, 200));
                    throw new Error(`Server returned non-JSON response. Status: ${response.status}`);
                }
                
                if (!response.ok) {
                    const errorData = await response.json().catch((parseError) => {
                        console.error('❌ Failed to parse error response:', parseError);
                        return { message: `HTTP error! status: ${response.status}` };
                    });
                    throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
                }
                
                const data = await response.json();
                console.log('✅ Response data:', data);
                
                if (data.success) {
                    // Add memory to the beginning of the array
                    if (data.memory) {
                        memories.unshift(data.memory);
                        displayMemories();
                    }
                    uploadForm.reset();
                    if (previewImage) previewImage.style.display = 'none';
                    if (uploaderName) uploaderName.value = '';
                    alert('Memory shared successfully!');
                } else {
                    alert(data.message || 'Failed to upload memory');
                }
            } catch (error) {
                console.error('❌ Error uploading memory:', error);
                console.error('❌ Error stack:', error.stack);
                
                // Provide more specific error messages
                let errorMessage = 'Failed to upload memory. Please try again.';
                if (error.message.includes('NetworkError') || error.message.includes('Failed to fetch')) {
                    errorMessage = 'Network error: Could not connect to server. Please check your internet connection and try again.';
                } else if (error.message.includes('non-JSON')) {
                    errorMessage = 'Server error: Invalid response from server. Please try again later.';
                } else {
                    errorMessage = 'Error: ' + error.message;
                }
                
                alert(errorMessage);
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Share This Memory';
                }
            }
        });
    }
}

// ========== VOICE MESSAGE ==========
function initVoicePlayer(audioUrl, hostName) {
    const playerContainer = document.getElementById('voice-message-player');
    if (!playerContainer || !audioUrl) return;
    
    let isPlaying = false;
    let hasPlayed = false;
    const audio = document.getElementById('voice-audio') || new Audio(audioUrl);
    if (!audio.src) audio.src = audioUrl;
    
    const playPauseBtn = document.getElementById('voice-play-pause-btn');
    const instructionText = document.getElementById('voice-instruction');
    
    function togglePlay() {
        if (isPlaying) {
            audio.pause();
        } else {
            audio.play();
            hasPlayed = true;
        }
    }
    
    audio.addEventListener('play', () => {
        isPlaying = true;
        if (playPauseBtn) {
            playPauseBtn.classList.add('playing');
            // Show waveform animation
            playPauseBtn.innerHTML = `
                <div class="voice-waveform-animation">
                    <div class="voice-wave-bar"></div>
                    <div class="voice-wave-bar"></div>
                    <div class="voice-wave-bar"></div>
                    <div class="voice-wave-bar"></div>
                    <div class="voice-wave-bar"></div>
                </div>
            `;
        }
        if (instructionText) instructionText.textContent = 'Playing...';
    });
    
    audio.addEventListener('pause', () => {
        isPlaying = false;
        if (playPauseBtn) {
            playPauseBtn.classList.remove('playing');
            // Show play icon
            playPauseBtn.innerHTML = `
                <svg width="48" height="48" viewBox="0 0 24 24" fill="white">
                    <path d="M8 5v14l11-7z"/>
                </svg>
            `;
        }
        if (instructionText && hasPlayed) instructionText.textContent = 'Tap to replay';
    });
    
    audio.addEventListener('ended', () => {
        isPlaying = false;
        if (playPauseBtn) {
            playPauseBtn.classList.remove('playing');
            playPauseBtn.innerHTML = `
                <svg width="48" height="48" viewBox="0 0 24 24" fill="white">
                    <path d="M8 5v14l11-7z"/>
                </svg>
            `;
        }
        if (instructionText) instructionText.textContent = 'Tap to replay';
    });
    
    if (playPauseBtn) {
        playPauseBtn.addEventListener('click', togglePlay);
    }
}

// ========== VOICE RECORDER (For Host) ==========
function initVoiceRecorder(invitationId) {
    const recorderContainer = document.getElementById('voice-recorder-container');
    if (!recorderContainer) return;
    
    let mediaRecorder = null;
    let audioChunks = [];
    let isRecording = false;
    const MAX_RECORDING_TIME = 30; // seconds
    let recordingTime = 0;
    let timerInterval = null;
    
    const startBtn = document.getElementById('voice-record-start');
    const stopBtn = document.getElementById('voice-record-stop');
    const timerDisplay = document.getElementById('voice-timer');
    const waveform = document.getElementById('voice-waveform');
    const audioPlayer = document.getElementById('voice-audio-preview');
    const reRecordBtn = document.getElementById('voice-rerecord-btn');
    const confirmBtn = document.getElementById('voice-confirm-btn');
    const recordingSection = document.getElementById('voice-recording-section');
    const playbackSection = document.getElementById('voice-playback-section');
    
    async function startRecording() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaRecorder = new MediaRecorder(stream);
            audioChunks = [];
            
            mediaRecorder.ondataavailable = (e) => {
                if (e.data.size > 0) {
                    audioChunks.push(e.data);
                }
            };
            
            mediaRecorder.onstop = () => {
                const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                const audioUrl = URL.createObjectURL(audioBlob);
                
                if (audioPlayer) {
                    audioPlayer.src = audioUrl;
                    audioPlayer.style.display = 'block';
                }
                
                if (recordingSection) recordingSection.style.display = 'none';
                if (playbackSection) playbackSection.style.display = 'block';
                
                // Stop all tracks
                stream.getTracks().forEach(track => track.stop());
            };
            
            mediaRecorder.start();
            isRecording = true;
            recordingTime = 0;
            
            if (startBtn) startBtn.style.display = 'none';
            if (stopBtn) stopBtn.style.display = 'block';
            if (waveform) waveform.style.display = 'flex';
            
            // Start timer
            timerInterval = setInterval(() => {
                recordingTime++;
                if (timerDisplay) {
                    timerDisplay.textContent = `${recordingTime}s / ${MAX_RECORDING_TIME}s`;
                }
                
                if (recordingTime >= MAX_RECORDING_TIME) {
                    stopRecording();
                }
            }, 1000);
            
        } catch (error) {
            console.error('Error accessing microphone:', error);
            alert('Please allow microphone access to record your message');
        }
    }
    
    function stopRecording() {
        if (mediaRecorder && isRecording) {
            mediaRecorder.stop();
            isRecording = false;
            
            if (timerInterval) {
                clearInterval(timerInterval);
                timerInterval = null;
            }
            
            if (stopBtn) stopBtn.style.display = 'none';
            if (waveform) waveform.style.display = 'none';
        }
    }
    
    async function uploadVoiceMessage() {
        if (audioChunks.length === 0) {
            alert('No recording to upload');
            return;
        }
        
        const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
        const formData = new FormData();
        formData.append('audio', audioBlob, 'voice-message.webm');
        formData.append('duration', recordingTime);
        
        if (confirmBtn) {
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Uploading...';
        }
        
        try {
            const response = await fetch(`/api/invitations/${invitationId}/voice-message`, {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (data.success) {
                alert('Voice message uploaded successfully!');
                window.location.reload();
            } else {
                alert(data.message || 'Failed to upload voice message');
            }
        } catch (error) {
            console.error('Error uploading voice message:', error);
            alert('Failed to upload voice message. Please try again.');
        } finally {
            if (confirmBtn) {
                confirmBtn.disabled = false;
                confirmBtn.textContent = '✓ Use This Recording';
            }
        }
    }
    
    function reRecord() {
        audioChunks = [];
        recordingTime = 0;
        if (audioPlayer) {
            audioPlayer.src = '';
            audioPlayer.style.display = 'none';
        }
        if (recordingSection) recordingSection.style.display = 'block';
        if (playbackSection) playbackSection.style.display = 'none';
        if (startBtn) startBtn.style.display = 'block';
        if (stopBtn) stopBtn.style.display = 'none';
    }
    
    if (startBtn) startBtn.addEventListener('click', startRecording);
    if (stopBtn) stopBtn.addEventListener('click', stopRecording);
    if (reRecordBtn) reRecordBtn.addEventListener('click', reRecord);
    if (confirmBtn) confirmBtn.addEventListener('click', uploadVoiceMessage);
}

