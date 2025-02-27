/* File: static/js/ui-components.js */
/**
 * UI Component enhancements for Le Repertoire
 * 
 * Provides reusable UI components for improved user experience:
 * - Loading indicators
 * - Toast notifications
 * - Form validation feedback
 * - Accessible form components
 * - Error handling
 */

/**
 * Close a modal by ID
 * Global function for use in modal HTML
 * @param {string} modalId - The ID of the modal to close
 */
window.closeModal = function(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('hidden');
    }
};

/**
 * Loading Indicator Component
 * Creates and manages loading overlays for async operations
 */
class LoadingIndicator {
    /**
     * Initialize the loading indicator
     * @param {Object} options - Configuration options
     * @param {string} options.containerId - ID of container element (default: 'loading-overlay')
     * @param {string} options.spinnerClass - CSS class for spinner (default: 'loading-spinner')
     * @param {string} options.message - Optional loading message
     * @param {boolean} options.fullscreen - Whether overlay should be fullscreen (default: true)
     */
    constructor(options = {}) {
        this.containerId = options.containerId || 'loading-overlay';
        this.spinnerClass = options.spinnerClass || 'loading-spinner';
        this.message = options.message || 'Loading...';
        this.fullscreen = options.fullscreen !== undefined ? options.fullscreen : true;
        
        this.container = document.getElementById(this.containerId);
        
        // Create container if it doesn't exist
        if (!this.container) {
            this.container = this._createContainer();
        }
        
        // Track active loading states
        this.activeLoadings = 0;
    }
    
    /**
     * Show the loading indicator
     * @param {string} message - Optional message to display
     * @returns {function} Hide function that can be called to hide this specific loading instance
     */
    show(message) {
        // Update message if provided
        if (message) {
            const messageEl = this.container.querySelector('.loading-message');
            if (messageEl) {
                messageEl.textContent = message;
            }
        }
        
        // Show container
        this.container.classList.remove('hidden');
        this.activeLoadings++;
        
        // Make container visible to screen readers
        this.container.setAttribute('aria-hidden', 'false');
        
        // Return function to hide this specific loading instance
        return () => {
            this.activeLoadings--;
            if (this.activeLoadings <= 0) {
                this.hide();
            }
        };
    }
    
    /**
     * Hide the loading indicator
     */
    hide() {
        this.activeLoadings = 0;
        this.container.classList.add('hidden');
        this.container.setAttribute('aria-hidden', 'true');
    }
    
    /**
     * Create the loading container
     * @returns {HTMLElement} The created container
     * @private
     */
    _createContainer() {
        const container = document.createElement('div');
        container.id = this.containerId;
        container.className = `fixed inset-0 flex items-center justify-center bg-white bg-opacity-75 z-50 hidden`;
        container.setAttribute('role', 'alert');
        container.setAttribute('aria-busy', 'true');
        container.setAttribute('aria-hidden', 'true');
        container.setAttribute('aria-label', 'Loading');
        
        const content = document.createElement('div');
        content.className = 'flex flex-col items-center';
        
        const spinner = document.createElement('div');
        spinner.className = `animate-spin rounded-full h-12 w-12 border-b-2 border-amber-600 ${this.spinnerClass}`;
        
        const message = document.createElement('p');
        message.className = 'loading-message mt-4 text-amber-800 font-medium';
        message.textContent = this.message;
        
        content.appendChild(spinner);
        content.appendChild(message);
        container.appendChild(content);
        
        document.body.appendChild(container);
        
        return container;
    }
    
    /**
     * Wrap an async function with loading indicator
     * @param {Function} asyncFn - Async function to wrap
     * @param {string} message - Optional loading message
     * @returns {Function} Wrapped function
     */
    static async wrap(asyncFn, message = 'Loading...') {
        const loading = new LoadingIndicator({ message });
        const hideLoading = loading.show();
        
        try {
            return await asyncFn();
        } finally {
            hideLoading();
        }
    }
}

/**
 * Toast Notification Component
 * Shows non-intrusive notifications
 */
class ToastNotification {
    /**
     * Initialize the toast notification system
     * @param {Object} options - Configuration options
     * @param {string} options.containerId - ID of container element (default: 'toast-container')
     * @param {number} options.duration - Default duration in ms (default: 3000)
     * @param {string} options.position - Position of toasts (default: 'top-right')
     */
    constructor(options = {}) {
        this.containerId = options.containerId || 'toast-container';
        this.duration = options.duration || 3000;
        this.position = options.position || 'top-right';
        
        this.container = document.getElementById(this.containerId);
        
        // Create container if it doesn't exist
        if (!this.container) {
            this.container = this._createContainer();
        }
    }
    
    /**
     * Show a toast notification
     * @param {string} message - Message to display
     * @param {string} type - Notification type: 'success', 'error', 'info', 'warning'
     * @param {number} duration - Duration in ms (default: this.duration)
     */
    show(message, type = 'info', duration = this.duration) {
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `
            notification p-4 rounded shadow-md max-w-md transform transition-all duration-300 opacity-0 translate-x-full
            ${type === 'success' ? 'bg-green-100 text-green-800 border-l-4 border-green-500' : ''}
            ${type === 'error' ? 'bg-red-100 text-red-800 border-l-4 border-red-500' : ''}
            ${type === 'warning' ? 'bg-yellow-100 text-yellow-800 border-l-4 border-yellow-500' : ''}
            ${type === 'info' ? 'bg-blue-100 text-blue-800 border-l-4 border-blue-500' : ''}
        `;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'polite');
        
        // Add icon based on type
        const iconMap = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle'
        };
        
        toast.innerHTML = `
            <div class="flex items-center">
                <i class="fas ${iconMap[type] || iconMap.info} mr-3" aria-hidden="true"></i>
                <p>${message}</p>
                <button class="ml-auto text-gray-500 hover:text-gray-700 focus:outline-none" aria-label="Close">
                    <i class="fas fa-times" aria-hidden="true"></i>
                </button>
            </div>
        `;
        
        // Add to container
        this.container.appendChild(toast);
        
        // Setup close button
        const closeButton = toast.querySelector('button');
        closeButton.addEventListener('click', () => {
            this._removeToast(toast);
        });
        
        // Trigger animation after a small delay (for proper transition)
        setTimeout(() => {
            toast.classList.remove('opacity-0', 'translate-x-full');
        }, 10);
        
        // Auto-remove after duration
        const timeout = setTimeout(() => {
            this._removeToast(toast);
        }, duration);
        
        // Store timeout id on toast element
        toast._timeoutId = timeout;
        
        return toast;
    }
    
    /**
     * Show a success toast
     * @param {string} message - Message to display
     * @param {number} duration - Duration in ms
     */
    success(message, duration) {
        return this.show(message, 'success', duration);
    }
    
    /**
     * Show an error toast
     * @param {string} message - Message to display
     * @param {number} duration - Duration in ms
     */
    error(message, duration) {
        return this.show(message, 'error', duration);
    }
    
    /**
     * Show a warning toast
     * @param {string} message - Message to display
     * @param {number} duration - Duration in ms
     */
    warning(message, duration) {
        return this.show(message, 'warning', duration);
    }
    
    /**
     * Show an info toast
     * @param {string} message - Message to display
     * @param {number} duration - Duration in ms
     */
    info(message, duration) {
        return this.show(message, 'info', duration);
    }
    
    /**
     * Remove a toast element
     * @param {HTMLElement} toast - Toast element to remove
     * @private
     */
    _removeToast(toast) {
        // Clear any existing timeout
        if (toast._timeoutId) {
            clearTimeout(toast._timeoutId);
        }
        
        // Add exit animation
        toast.classList.add('opacity-0', 'translate-x-full');
        
        // Remove after animation
        setTimeout(() => {
            if (toast.parentNode === this.container) {
                this.container.removeChild(toast);
            }
        }, 300);
    }
    
    /**
     * Create the toast container
     * @returns {HTMLElement} The created container
     * @private
     */
    _createContainer() {
        const container = document.createElement('div');
        container.id = this.containerId;
        
        // Set position classes
        const positionClasses = {
            'top-right': 'fixed top-5 right-5 z-50 flex flex-col gap-3',
            'top-left': 'fixed top-5 left-5 z-50 flex flex-col gap-3',
            'bottom-right': 'fixed bottom-5 right-5 z-50 flex flex-col gap-3',
            'bottom-left': 'fixed bottom-5 left-5 z-50 flex flex-col gap-3',
            'top-center': 'fixed top-5 left-1/2 transform -translate-x-1/2 z-50 flex flex-col gap-3',
            'bottom-center': 'fixed bottom-5 left-1/2 transform -translate-x-1/2 z-50 flex flex-col gap-3'
        };
        
        container.className = positionClasses[this.position] || positionClasses['top-right'];
        
        document.body.appendChild(container);
        
        return container;
    }
}

/**
 * Form Validation Component
 * Provides enhanced form validation with detailed feedback
 */
class FormValidator {
    /**
     * Initialize form validation
     * @param {HTMLFormElement} form - Form element to validate
     * @param {Object} options - Configuration options
     * @param {Object} options.customValidators - Custom validation functions
     * @param {Function} options.onSubmit - Submit handler
     * @param {boolean} options.validateOnInput - Whether to validate on input (default: true)
     * @param {boolean} options.focusOnError - Whether to focus on first error field (default: true)
     */
    constructor(form, options = {}) {
        this.form = form;
        this.customValidators = options.customValidators || {};
        this.onSubmit = options.onSubmit;
        this.validateOnInput = options.validateOnInput !== undefined ? options.validateOnInput : true;
        this.focusOnError = options.focusOnError !== undefined ? options.focusOnError : true;
        
        // Track validation state
        this.errors = {};
        this.isValid = true;
        
        // Initialize form
        this._init();
    }
    
    /**
     * Initialize validation
     * @private
     */
    _init() {
        if (!this.form) return;
        
        // Add validation attributes
        this._initializeFields();
        
        // Add submit handler
        this.form.addEventListener('submit', (event) => {
            // Prevent default form submission
            event.preventDefault();
            
            // Validate form
            const isValid = this.validate();
            
            // If valid and onSubmit handler provided, call it
            if (isValid && this.onSubmit) {
                this.onSubmit(event, this.getFormData());
            }
            
            // If not valid, show error summary
            if (!isValid) {
                this._showErrorSummary();
            }
        });
        
        // Add input handlers for real-time validation
        if (this.validateOnInput) {
            this.form.querySelectorAll('input, select, textarea').forEach(field => {
                field.addEventListener('input', () => {
                    this._validateField(field);
                    this._updateSubmitButton();
                });
                
                field.addEventListener('blur', () => {
                    this._validateField(field);
                    this._updateSubmitButton();
                });
            });
        }
        
        // Initial validation
        this.validate();
        this._updateSubmitButton();
    }
    
    /**
     * Initialize field attributes
     * @private
     */
    _initializeFields() {
        const fields = this.form.querySelectorAll('input, select, textarea');
        
        fields.forEach(field => {
            // Add aria attributes
            if (field.required && !field.hasAttribute('aria-required')) {
                field.setAttribute('aria-required', 'true');
            }
            
            if (!field.hasAttribute('aria-invalid')) {
                field.setAttribute('aria-invalid', 'false');
            }
            
            // Add validation state classes
            if (!field.classList.contains('input-field')) {
                field.classList.add('input-field');
            }
            
            // Create error message container if needed
            const fieldId = field.id || field.name;
            const errorId = `${fieldId}-error`;
            
            let errorElement = document.getElementById(errorId);
            if (!errorElement) {
                errorElement = document.createElement('p');
                errorElement.id = errorId;
                errorElement.className = 'error-message text-sm text-red-600 mt-1 hidden';
                errorElement.setAttribute('aria-live', 'polite');
                
                // Insert after field
                field.parentNode.insertBefore(errorElement, field.nextSibling);
            }
            
            // Connect field to error message
            field.setAttribute('aria-describedby', errorId);
        });
    }
    
    /**
     * Validate the entire form
     * @returns {boolean} Whether the form is valid
     */
    validate() {
        this.errors = {};
        this.isValid = true;
        
        const fields = this.form.querySelectorAll('input, select, textarea');
        
        fields.forEach(field => {
            this._validateField(field);
        });
        
        // Update UI
        this._updateSubmitButton();
        
        // Focus first error field
        if (!this.isValid && this.focusOnError) {
            const firstErrorField = this.form.querySelector('.input-field.invalid');
            if (firstErrorField) {
                firstErrorField.focus();
            }
        }
        
        return this.isValid;
    }
    
    /**
     * Validate a single field
     * @param {HTMLElement} field - Field to validate
     * @returns {boolean} Whether the field is valid
     * @private
     */
    _validateField(field) {
        const value = field.value.trim();
        const fieldId = field.id || field.name;
        const required = field.hasAttribute('required');
        const pattern = field.getAttribute('pattern');
        const minLength = field.getAttribute('minlength');
        const maxLength = field.getAttribute('maxLength');
        const min = field.getAttribute('min');
        const max = field.getAttribute('max');
        const type = field.getAttribute('type');
        
        // Reset field validation state
        field.classList.remove('valid', 'invalid');
        field.setAttribute('aria-invalid', 'false');
        
        // Find error element
        const errorElement = document.getElementById(`${fieldId}-error`);
        if (errorElement) {
            errorElement.textContent = '';
            errorElement.classList.add('hidden');
        }
        
        // Valid by default
        let isValid = true;
        let errorMessage = '';
        
        // Check required
        if (required && !value) {
            isValid = false;
            errorMessage = 'This field is required';
        }
        
        // Skip other validations if empty and not required
        if (!value && !required) {
            // Field is valid (empty but not required)
            this._setFieldState(field, true);
            return true;
        }
        
        // Check pattern
        if (isValid && pattern && !new RegExp(pattern).test(value)) {
            isValid = false;
            errorMessage = field.getAttribute('data-pattern-message') || 'Invalid format';
        }
        
        // Check minlength
        if (isValid && minLength && value.length < parseInt(minLength)) {
            isValid = false;
            errorMessage = `Minimum length is ${minLength} characters`;
        }
        
        // Check maxlength
        if (isValid && maxLength && value.length > parseInt(maxLength)) {
            isValid = false;
            errorMessage = `Maximum length is ${maxLength} characters`;
        }
        
        // Check numeric constraints
        if (isValid && (type === 'number' || type === 'range')) {
            const numValue = parseFloat(value);
            if (isNaN(numValue)) {
                isValid = false;
                errorMessage = 'Must be a number';
            } else if (min !== null && numValue < parseFloat(min)) {
                isValid = false;
                errorMessage = `Minimum value is ${min}`;
            } else if (max !== null && numValue > parseFloat(max)) {
                isValid = false;
                errorMessage = `Maximum value is ${max}`;
            }
        }
        
        // Check email format
        if (isValid && type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
            isValid = false;
            errorMessage = 'Invalid email address';
        }
        
        // Custom validators
        if (isValid && this.customValidators[fieldId]) {
            const customValidation = this.customValidators[fieldId](value, field);
            if (customValidation !== true) {
                isValid = false;
                errorMessage = customValidation || 'Invalid value';
            }
        }
        
        // Update field state
        this._setFieldState(field, isValid, errorMessage);
        
        // Update global validation state
        if (!isValid) {
            this.errors[fieldId] = errorMessage;
            this.isValid = false;
        }
        
        return isValid;
    }
    
    /**
     * Set field validation state
     * @param {HTMLElement} field - Field to update
     * @param {boolean} isValid - Whether the field is valid
     * @param {string} errorMessage - Error message to display
     * @private
     */
    _setFieldState(field, isValid, errorMessage = '') {
        // Find error element
        const fieldId = field.id || field.name;
        const errorElement = document.getElementById(`${fieldId}-error`);
        
        // Update field styling
        if (isValid) {
            field.classList.add('valid');
            field.classList.remove('invalid');
            field.setAttribute('aria-invalid', 'false');
            
            if (errorElement) {
                errorElement.classList.add('hidden');
                errorElement.textContent = '';
            }
            
            // Show valid icon if exists
            const validIcon = field.parentElement.querySelector('.valid-icon');
            if (validIcon) {
                validIcon.classList.remove('hidden');
            }
        } else {
            field.classList.add('invalid');
            field.classList.remove('valid');
            field.setAttribute('aria-invalid', 'true');
            
            if (errorElement) {
                errorElement.classList.remove('hidden');
                errorElement.textContent = errorMessage;
            }
            
            // Hide valid icon if exists
            const validIcon = field.parentElement.querySelector('.valid-icon');
            if (validIcon) {
                validIcon.classList.add('hidden');
            }
        }
    }
    
    /**
     * Update submit button state
     * @private
     */
    _updateSubmitButton() {
        const submitButton = this.form.querySelector('button[type="submit"]');
        if (!submitButton) return;
        
        // Enable/disable button based on form validity
        submitButton.disabled = !this.isValid;
    }
    
    /**
     * Show error summary
     * @private
     */
    _showErrorSummary() {
        // Find or create error summary container
        let errorSummary = this.form.querySelector('.error-summary');
        if (!errorSummary) {
            errorSummary = document.createElement('div');
            errorSummary.className = 'error-summary bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded my-4';
            errorSummary.setAttribute('role', 'alert');
            errorSummary.setAttribute('aria-live', 'assertive');
            
            // Add to beginning of form
            this.form.insertBefore(errorSummary, this.form.firstChild);
        } else {
            errorSummary.classList.remove('hidden');
        }
        
        // Build error list
        let errorHtml = '<h3 class="font-bold">Please correct the following errors:</h3><ul class="list-disc ml-5 mt-2">';
        
        Object.entries(this.errors).forEach(([fieldId, message]) => {
            const field = this.form.querySelector(`#${fieldId}`);
            const fieldName = field ? (field.getAttribute('data-label') || field.name || fieldId) : fieldId;
            
            errorHtml += `<li><a href="#${fieldId}" class="underline">${fieldName}: ${message}</a></li>`;
        });
        
        errorHtml += '</ul>';
        
        // Update error summary content
        errorSummary.innerHTML = errorHtml;
        
        // Add click handlers to error links
        errorSummary.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', (event) => {
                event.preventDefault();
                
                // Get field ID from href
                const fieldId = link.getAttribute('href').substring(1);
                
                // Focus on field
                const field = document.getElementById(fieldId);
                if (field) {
                    field.focus();
                }
            });
        });
    }
    
    /**
     * Get form data as object
     * @returns {Object} Form data
     */
    getFormData() {
        const formData = new FormData(this.form);
        return Object.fromEntries(formData.entries());
    }
    
    /**
     * Reset form
     */
    reset() {
        this.form.reset();
        this.errors = {};
        this.isValid = true;
        
        // Reset field states
        this.form.querySelectorAll('input, select, textarea').forEach(field => {
            field.classList.remove('valid', 'invalid');
            field.setAttribute('aria-invalid', 'false');
            
            // Hide error message
            const fieldId = field.id || field.name;
            const errorElement = document.getElementById(`${fieldId}-error`);
            if (errorElement) {
                errorElement.classList.add('hidden');
                errorElement.textContent = '';
            }
            
            // Hide valid icon
            const validIcon = field.parentElement.querySelector('.valid-icon');
            if (validIcon) {
                validIcon.classList.add('hidden');
            }
        });
        
        // Hide error summary
        const errorSummary = this.form.querySelector('.error-summary');
        if (errorSummary) {
            errorSummary.classList.add('hidden');
        }
        
        // Update submit button
        this._updateSubmitButton();
    }
}

/**
 * Error Handling Module
 * Provides consistent error handling and reporting
 */
class ErrorHandler {
    /**
     * Initialize error handler
     * @param {Object} options - Configuration options
     * @param {ToastNotification} options.toast - Toast notification component (optional)
     * @param {Function} options.onError - Global error handler (optional)
     * @param {boolean} options.logToConsole - Whether to log errors to console (default: true)
     * @param {string} options.modalId - ID of error modal (default: 'error-modal')
     */
    constructor(options = {}) {
        this.toast = options.toast;
        this.onError = options.onError;
        this.logToConsole = options.logToConsole !== undefined ? options.logToConsole : true;
        this.modalId = options.modalId || 'error-modal';
    }
    
    /**
     * Handle an error
     * @param {Error|string} error - Error object or message
     * @param {Object} options - Error handling options
     * @param {string} options.title - Error title
     * @param {string} options.type - Error type ('toast', 'modal', 'both', 'silent')
     * @param {boolean} options.log - Whether to log to console (default: this.logToConsole)
     * @param {Function} options.callback - Callback after error is handled
     */
    handle(error, options = {}) {
        const errorMessage = error instanceof Error ? error.message : error;
        const errorTitle = options.title || 'Error';
        const errorType = options.type || 'toast';
        const shouldLog = options.log !== undefined ? options.log : this.logToConsole;
        
        // Log to console
        if (shouldLog) {
            console.error(errorTitle, error);
        }
        
        // Call global error handler
        if (this.onError) {
            this.onError(error, options);
        }
        
        // Show error toast
        if (errorType === 'toast' || errorType === 'both') {
            if (this.toast) {
                this.toast.error(errorMessage);
            } else {
                alert(`${errorTitle}: ${errorMessage}`);
            }
        }
        
        // Show error modal
        if (errorType === 'modal' || errorType === 'both') {
            this._showErrorModal(errorTitle, errorMessage);
        }
        
        // Call callback
        if (options.callback) {
            options.callback(error);
        }
    }
    
    /**
     * Handle API response error
     * @param {Response} response - Fetch API response
     * @param {Object} options - Error handling options
     */
    async handleApiError(response, options = {}) {
        try {
            // Try to parse response as JSON
            const data = await response.json();
            
            // Get error message
            const errorMessage = data.message || data.error || `API Error (${response.status})`;
            
            // Handle error
            this.handle(errorMessage, {
                title: options.title || 'API Error',
                type: options.type || 'toast',
                log: options.log,
                callback: options.callback
            });
            
            return data;
        } catch (e) {
            // Fallback if JSON parsing fails
            this.handle(`API error (${response.status})`, {
                title: options.title || 'API Error',
                type: options.type || 'toast',
                log: options.log,
                callback: options.callback
            });
            
            return null;
        }
    }
    
    /**
     * Show error modal
     * @param {string} title - Error title
     * @param {string} message - Error message
     * @private
     */
    _showErrorModal(title, message) {
        // Find or create modal
        let modal = document.getElementById(this.modalId);
        
        if (!modal) {
            modal = document.createElement('div');
            modal.id = this.modalId;
            modal.className = 'fixed inset-0 flex items-center justify-center bg-gray-900 bg-opacity-75 z-50 hidden';
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');
            
            modal.innerHTML = `
                <div class="bg-white rounded-lg shadow-lg p-6 w-full max-w-md mx-4">
                    <div class="flex justify-end">
                        <button onclick="closeModal('${this.modalId}')" 
                                class="text-gray-400 hover:text-gray-700"
                                aria-label="Close error modal">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <div class="text-center mb-6">
                        <h2 id="error-title" class="text-2xl font-bold text-gray-900">Error</h2>
                        <p id="error-message" class="text-sm text-gray-600 mt-1"></p>
                    </div>
                </div>
            `;
            
            document.body.appendChild(modal);
        }
        
        // Set modal content
        const titleElement = modal.querySelector('#error-title');
        const messageElement = modal.querySelector('#error-message');
        
        if (titleElement) titleElement.textContent = title;
        if (messageElement) messageElement.textContent = message;
        
        // Show modal
        modal.classList.remove('hidden');
    }
}

// Export components
window.UIComponents = {
    LoadingIndicator,
    ToastNotification,
    FormValidator,
    ErrorHandler
};
