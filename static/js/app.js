// EventCraft Pro - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Theme switching functionality
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');
    const htmlElement = document.documentElement;
    
    // Load saved theme from localStorage
    const savedTheme = localStorage.getItem('theme') || 'light';
    htmlElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
    
    // Theme toggle click handler
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const currentTheme = htmlElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            
            htmlElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon(newTheme);
            
            // Dispatch custom event for other components
            window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme: newTheme } }));
        });
    }
    
    // Update theme icon based on current theme
    function updateThemeIcon(theme) {
        if (themeIcon) {
            if (theme === 'dark') {
                themeIcon.className = 'fas fa-moon';
                themeIcon.style.color = '#ffffff';
                themeIcon.title = 'Switch to Light Theme';
            } else {
                themeIcon.className = 'fas fa-sun';
                themeIcon.style.color = '#ffffff';
                themeIcon.title = 'Switch to Dark Theme';
            }
        }
    }
    
    // Check for system preference and apply if no saved theme
    if (!localStorage.getItem('theme')) {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const systemTheme = prefersDark ? 'dark' : 'light';
        htmlElement.setAttribute('data-theme', systemTheme);
        localStorage.setItem('theme', systemTheme);
        updateThemeIcon(systemTheme);
    }
    
    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(e) {
        if (!localStorage.getItem('theme')) {
            const systemTheme = e.matches ? 'dark' : 'light';
            htmlElement.setAttribute('data-theme', systemTheme);
            localStorage.setItem('theme', systemTheme);
            updateThemeIcon(systemTheme);
        }
    });
    
    // Function to get current theme (for other components)
    window.getCurrentTheme = function() {
        return htmlElement.getAttribute('data-theme') || 'light';
    };
    
    // Function to set theme programmatically
    window.setTheme = function(theme) {
        if (theme === 'light' || theme === 'dark') {
            htmlElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            updateThemeIcon(theme);
            window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme: theme } }));
        }
    };

    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        if (alert.classList.contains('alert-success') || alert.classList.contains('alert-info')) {
            setTimeout(function() {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        }
    });

    // Form validation enhancement
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    // Add loading state to buttons on form submit
    const submitButtons = document.querySelectorAll('button[type="submit"]');
    submitButtons.forEach(function(button) {
        const form = button.closest('form');
        if (form) {
            form.addEventListener('submit', function() {
                button.classList.add('loading');
                button.disabled = true;
                
                // Re-enable button after 10 seconds as failsafe
                setTimeout(function() {
                    button.classList.remove('loading');
                    button.disabled = false;
                }, 10000);
            });
        }
    });

    // Smooth scrolling for anchor links
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                e.preventDefault();
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Copy to clipboard functionality
    window.copyToClipboard = function(text, button) {
        navigator.clipboard.writeText(text).then(function() {
            // Show success feedback
            const originalHtml = button.innerHTML;
            button.innerHTML = '<i class="fas fa-check"></i> Copied!';
            button.classList.add('btn-success');
            
            setTimeout(function() {
                button.innerHTML = originalHtml;
                button.classList.remove('btn-success');
            }, 2000);
        }).catch(function(err) {
            console.error('Failed to copy text: ', err);
        });
    };

    // Animation on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(function(entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
            }
        });
    }, observerOptions);

    // Observe elements for animation
    const animatedElements = document.querySelectorAll('.card, .event-type-card');
    animatedElements.forEach(function(element) {
        observer.observe(element);
    });

    // Enhanced form handling for RSVP
    const rsvpForm = document.querySelector('.rsvp-form');
    if (rsvpForm) {
        const responseInputs = rsvpForm.querySelectorAll('input[name="response"]');
        const guestCountField = rsvpForm.querySelector('#guest_count');
        
        responseInputs.forEach(function(input) {
            input.addEventListener('change', function() {
                if (this.value === 'no') {
                    guestCountField.value = '0';
                    guestCountField.disabled = true;
                } else {
                    guestCountField.disabled = false;
                    if (guestCountField.value === '0') {
                        guestCountField.value = '1';
                    }
                }
            });
        });
    }

    // Auto-resize textareas
    const textareas = document.querySelectorAll('textarea');
    textareas.forEach(function(textarea) {
        textarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    });

    // Phone number formatting
    const phoneInputs = document.querySelectorAll('input[type="tel"]');
    phoneInputs.forEach(function(input) {
        input.addEventListener('input', function() {
            let value = this.value.replace(/\D/g, '');
            if (value.length >= 6) {
                value = value.replace(/(\d{3})(\d{3})(\d{4})/, '($1) $2-$3');
            } else if (value.length >= 3) {
                value = value.replace(/(\d{3})(\d{0,3})/, '($1) $2');
            }
            this.value = value;
        });
    });

    // Date input minimum date
    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(function(input) {
        if (!input.min) {
            const today = new Date().toISOString().split('T')[0];
            input.min = today;
        }
    });

    // Dashboard stats animation
    const statNumbers = document.querySelectorAll('.card .display-6');
    statNumbers.forEach(function(element) {
        const textContent = element.textContent.trim();
        const finalValue = parseInt(textContent);
        
        // Only animate if it's a valid number
        if (!isNaN(finalValue) && finalValue >= 0) {
            let currentValue = 0;
            const increment = Math.ceil(finalValue / 20);
            
            const timer = setInterval(function() {
                currentValue += increment;
                if (currentValue >= finalValue) {
                    currentValue = finalValue;
                    clearInterval(timer);
                }
                element.textContent = currentValue;
            }, 50);
        }
    });

    // Template selection enhancement
    const templateCards = document.querySelectorAll('.template-label');
    templateCards.forEach(function(card) {
        card.addEventListener('click', function() {
            // Remove active class from all cards
            templateCards.forEach(function(c) {
                c.classList.remove('border-primary', 'shadow-lg');
            });
            
            // Add active class to clicked card
            this.classList.add('border-primary', 'shadow-lg');
        });
    });

    // Keyboard navigation for template selection
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            const focusedElement = document.activeElement;
            if (focusedElement && focusedElement.classList.contains('template-label')) {
                e.preventDefault();
                focusedElement.click();
            }
        }
    });
});

// Utility functions
window.utils = {
    formatDate: function(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    },

    formatTime: function(timeString) {
        const time = new Date('2000-01-01 ' + timeString);
        return time.toLocaleTimeString('en-US', {
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        });
    },

    showToast: function(message, type = 'info') {
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        // Add to toast container or create one
        let toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
            document.body.appendChild(toastContainer);
        }

        toastContainer.appendChild(toast);

        // Show toast
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();

        // Remove from DOM after hiding
        toast.addEventListener('hidden.bs.toast', function() {
            toast.remove();
        });
    },

    // Location functionality for Google Maps integration
    openLocation: function(venueAddress) {
        if (venueAddress && venueAddress.trim()) {
            const encodedAddress = encodeURIComponent(venueAddress.trim());
            const googleMapsUrl = `https://www.google.com/maps/search/?api=1&query=${encodedAddress}`;
            window.open(googleMapsUrl, '_blank');
        } else {
            this.showToast('Venue address not available', 'warning');
        }
    }
};

// Global function for backward compatibility
window.openLocation = function(venueAddress) {
    return window.utils.openLocation(venueAddress);
};
