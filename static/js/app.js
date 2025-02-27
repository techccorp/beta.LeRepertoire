/**
 * Main application JavaScript for Le Repertoire
 * 
 * Handles common functionality across the application:
 * - CSRF token management
 * - Form validation
 * - API requests
 * - Event handling
 */

// Global CSRF token management for all AJAX requests
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

/**
 * Configure all AJAX requests with CSRF token header
 */
function configureAjaxRequests() {
    // Add CSRF token to all AJAX requests
    document.addEventListener('DOMContentLoaded', () => {
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        if (csrfToken) {
            // Configure fetch requests with pre-request callback
            const originalFetch = window.fetch;
            window.fetch = function (resource, options = {}) {
                // Only add header for same-origin requests
                const url = resource instanceof Request ? resource.url : resource;
                const isSameOrigin = url.startsWith(window.location.origin) || !url.startsWith('http');
                
                if (isSameOrigin) {
                    // Create headers if needed
                    options.headers = options.headers || new Headers();
                    
                    // Add CSRF token header if not already present
                    if (options.headers instanceof Headers) {
                        if (!options.headers.has('X-CSRF-Token')) {
                            options.headers.append('X-CSRF-Token', csrfToken);
                        }
                    } else {
                        options.headers = {
                            ...options.headers,
                            'X-CSRF-Token': csrfToken
                        };
                    }
                }
                
                return originalFetch.call(window, resource, options);
            };
        }
    });
}

/**
 * Format currency values for display
 * 
 * @param {number} value - The value to format
 * @param {string} currencyCode - Currency code (default: AUD)
 * @returns {string} Formatted currency string
 */
function formatCurrency(value, currencyCode = 'AUD') {
    return new Intl.NumberFormat('en-AU', {
        style: 'currency',
        currency: currencyCode
    }).format(value);
}

/**
 * Format date for display
 * 
 * @param {string|Date} date - Date to format
 * @param {string} format - Format style (default: 'medium')
 * @returns {string} Formatted date string
 */
function formatDate(date, format = 'medium') {
    if (!date) return '';
    
    const dateObj = typeof date === 'string' ? new Date(date) : date;
    
    const options = {
        short: { day: 'numeric', month: 'numeric', year: '2-digit' },
        medium: { day: 'numeric', month: 'short', year: 'numeric' },
        long: { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }
    };
    
    return new Intl.DateTimeFormat('en-AU', options[format] || options.medium).format(dateObj);
}

/**
 * Show a notification message to the user
 * 
 * @param {string} message - The message to display
 * @param {string} type - Message type: 'success', 'error', 'info', 'warning'
 * @param {number} duration - Duration in milliseconds
 */
function showNotification(message, type = 'info', duration = 3000) {
    // Create notification element if it doesn't exist
    let notificationContainer = document.getElementById('notification-container');
    
    if (!notificationContainer) {
        notificationContainer = document.createElement('div');
        notificationContainer.id = 'notification-container';
        notificationContainer.className = 'fixed top-5 right-5 z-50 flex flex-col gap-3';
        document.body.appendChild(notificationContainer);
    }
    
    // Create notification
    const notification = document.createElement('div');
    notification.className = `
        notification p-4 rounded shadow-md max-w-md transform transition-all duration-300 
        ${type === 'success' ? 'bg-green-100 text-green-800 border-l-4 border-green-500' : ''}
        ${type === 'error' ? 'bg-red-100 text-red-800 border-l-4 border-red-500' : ''}
        ${type === 'warning' ? 'bg-yellow-100 text-yellow-800 border-l-4 border-yellow-500' : ''}
        ${type === 'info' ? 'bg-blue-100 text-blue-800 border-l-4 border-blue-500' : ''}
    `;
    
    // Add icon based on type
    const iconMap = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    
    notification.innerHTML = `
        <div class="flex items-center">
            <i class="fas ${iconMap[type] || iconMap.info} mr-3"></i>
            <p>${message}</p>
            <button class="ml-auto text-gray-500 hover:text-gray-700 focus:outline-none" aria-label="Close">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    // Add to container
    notificationContainer.appendChild(notification);
    
    // Setup close button
    const closeButton = notification.querySelector('button');
    closeButton.addEventListener('click', () => {
        notification.classList.add('opacity-0', 'translate-x-full');
        setTimeout(() => {
            notification.remove();
        }, 300);
    });
    
    // Auto-remove after duration
    setTimeout(() => {
        notification.classList.add('opacity-0', 'translate-x-full');
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, duration);
}

/**
 * Validate a form field
 * 
 * @param {HTMLElement} field - Form field to validate
 * @returns {boolean} True if valid, false otherwise
 */
function validateField(field) {
    const value = field.value.trim();
    const required = field.hasAttribute('required');
    const pattern = field.getAttribute('pattern');
    const minLength = field.getAttribute('minlength');
    const maxLength = field.getAttribute('maxlength');
    const min = field.getAttribute('min');
    const max = field.getAttribute('max');
    const type = field.getAttribute('type');
    
    // Check required
    if (required && !value) {
        return setFieldState(field, false, 'This field is required');
    }
    
    // Skip other validations if empty and not required
    if (!value && !required) {
        return setFieldState(field, true);
    }
    
    // Check pattern
    if (pattern && !new RegExp(pattern).test(value)) {
        return setFieldState(field, false, 'Invalid format');
    }
    
    // Check minlength
    if (minLength && value.length < parseInt(minLength)) {
        return setFieldState(field, false, `Minimum length is ${minLength} characters`);
    }
    
    // Check maxlength
    if (maxLength && value.length > parseInt(maxLength)) {
        return setFieldState(field, false, `Maximum length is ${maxLength} characters`);
    }
    
    // Check numeric constraints
    if (type === 'number' || type === 'range') {
        const numValue = parseFloat(value);
        if (isNaN(numValue)) {
            return setFieldState(field, false, 'Must be a number');
        }
        
        if (min !== null && numValue < parseFloat(min)) {
            return setFieldState(field, false, `Minimum value is ${min}`);
        }
        
        if (max !== null && numValue > parseFloat(max)) {
            return setFieldState(field, false, `Maximum value is ${max}`);
        }
    }
    
    // Check email format
    if (type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        return setFieldState(field, false, 'Invalid email address');
    }
    
    // All validations passed
    return setFieldState(field, true);
}

/**
 * Set field validation state
 * 
 * @param {HTMLElement} field - Form field to update
 * @param {boolean} isValid - Whether the field is valid
 * @param {string} errorMessage - Error message to display
 * @returns {boolean} The isValid parameter
 */
function setFieldState(field, isValid, errorMessage = '') {
    // Find or create error message element
    let errorElement = field.nextElementSibling;
    if (!errorElement || !errorElement.classList.contains('error-message')) {
        errorElement = document.createElement('p');
        errorElement.className = 'error-message text-sm text-red-600 mt-1 hidden';
        field.parentNode.insertBefore(errorElement, field.nextSibling);
    }
    
    // Update field styling
    if (isValid) {
        field.classList.remove('border-red-500');
        field.classList.add('border-green-500');
        errorElement.classList.add('hidden');
    } else {
        field.classList.remove('border-green-500');
        field.classList.add('border-red-500');
        errorElement.textContent = errorMessage;
        errorElement.classList.remove('hidden');
    }
    
    return isValid;
}

/**
 * Initialize common application features
 */
function initializeApp() {
    configureAjaxRequests();
    
    // Add form validation
    document.addEventListener('submit', (event) => {
        const form = event.target;
        if (form.classList.contains('validate-form')) {
            const fields = form.querySelectorAll('input, select, textarea');
            let isValid = true;
            
            fields.forEach(field => {
                if (!validateField(field)) {
                    isValid = false;
                }
            });
            
            if (!isValid) {
                event.preventDefault();
                event.stopPropagation();
                showNotification('Please correct the errors in the form', 'error');
            }
        }
    });
}

// Initialize on document load
document.addEventListener('DOMContentLoaded', initializeApp);

// Export utility functions
window.LeRepertoire = {
    formatCurrency,
    formatDate,
    showNotification,
    validateField
};
