// Common Login Service - Main JavaScript

// API Helper
const api = {
    async request(url, options = {}) {
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
        };
        
        const response = await fetch(url, { ...defaultOptions, ...options });
        return response.json();
    },
    
    async get(url) {
        return this.request(url, { method: 'GET' });
    },
    
    async post(url, data) {
        return this.request(url, {
            method: 'POST',
            body: JSON.stringify(data),
        });
    },
    
    async put(url, data) {
        return this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data),
        });
    },
    
    async delete(url) {
        return this.request(url, { method: 'DELETE' });
    },
};

// Dark Mode Functions
const darkMode = {
    storageKey: 'dark-mode-preference',
    serverSetting: null, // Backend configured dark mode setting: 'system', 'dark', 'light'
    
    // Set the server-side dark mode configuration
    setServerSetting(setting) {
        this.serverSetting = setting;
    },
    
    // Get current theme preference based on server setting and user preference
    getPreference() {
        // If server forces dark or light mode, respect that
        if (this.serverSetting === 'dark') {
            return true;
        }
        if (this.serverSetting === 'light') {
            return false;
        }
        
        // Server setting is 'system' or not set - use user preference or system default
        const stored = localStorage.getItem(this.storageKey);
        if (stored !== null) {
            return stored === 'true';
        }
        // Check system preference
        return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    },
    
    // Check if user can toggle dark mode (only when server allows 'system' mode)
    canToggle() {
        return !this.serverSetting || this.serverSetting === 'system';
    },
    
    // Set theme preference
    setPreference(isDark) {
        if (!this.canToggle()) {
            return; // Don't allow toggle if server forces a mode
        }
        localStorage.setItem(this.storageKey, isDark);
        this.applyTheme(isDark);
    },
    
    // Apply theme to document
    applyTheme(isDark) {
        document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
        this.updateToggleIcon(isDark);
    },
    
    // Update toggle button icon
    updateToggleIcon(isDark) {
        const toggleBtns = document.querySelectorAll('.dark-mode-toggle i');
        toggleBtns.forEach(icon => {
            if (isDark) {
                icon.classList.remove('bi-moon-fill');
                icon.classList.add('bi-sun-fill');
            } else {
                icon.classList.remove('bi-sun-fill');
                icon.classList.add('bi-moon-fill');
            }
        });
        
        // Hide toggle button if server forces a mode
        if (!this.canToggle()) {
            document.querySelectorAll('.dark-mode-toggle').forEach(btn => {
                btn.style.display = 'none';
            });
        }
    },
    
    // Toggle dark mode
    toggle() {
        if (!this.canToggle()) {
            return; // Don't allow toggle if server forces a mode
        }
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const isDark = currentTheme !== 'dark';
        this.setPreference(isDark);
    },
    
    // Initialize dark mode on page load
    init(serverSetting) {
        if (serverSetting) {
            this.serverSetting = serverSetting;
        }
        const isDark = this.getPreference();
        this.applyTheme(isDark);
        
        // Listen for system preference changes (only if in 'system' mode)
        if (window.matchMedia && this.canToggle()) {
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
                // Only update if user hasn't set a manual preference
                if (localStorage.getItem(this.storageKey) === null) {
                    this.applyTheme(e.matches);
                }
            });
        }
    }
};

// Toast Notification
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container') || createToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    document.body.appendChild(container);
    return container;
}

// Loading Overlay
function showLoading() {
    let overlay = document.getElementById('loading-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loading-overlay';
        overlay.innerHTML = `
            <div class="loading-spinner">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        `;
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
        `;
        document.body.appendChild(overlay);
    }
    overlay.style.display = 'flex';
}

function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

// Form Validation Helper
function validateForm(form) {
    const inputs = form.querySelectorAll('[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            input.classList.add('is-invalid');
            isValid = false;
        } else {
            input.classList.remove('is-invalid');
        }
    });
    
    return isValid;
}

// Toggle dark mode function (for onclick handlers)
function toggleDarkMode() {
    darkMode.toggle();
}

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize dark mode with server setting if available
    // The serverDarkModeSetting variable is set by an inline script in the HTML template
    const serverSetting = typeof serverDarkModeSetting !== 'undefined' ? serverDarkModeSetting : null;
    darkMode.init(serverSetting);
    
    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
});

// Language Switcher
async function setLanguage(lang) {
    try {
        const response = await fetch('/api/i18n/set-language', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ lang: lang })
        });
        const data = await response.json();
        if (data.success) {
            window.location.reload();
        }
    } catch (error) {
        console.error('Failed to set language:', error);
    }
}
