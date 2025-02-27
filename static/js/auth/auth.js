/**
 * Authentication functionality for Le Repertoire
 */

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const payrollIdInput = document.getElementById('payroll-id');
    const passwordInput = document.getElementById('password');
    const loginSubmitBtn = document.getElementById('login-submit-btn');
    const loginErrors = document.getElementById('login-errors');
    const loadingOverlay = document.getElementById('loading-overlay');
    
    /**
     * Validate payroll ID format
     * @param {string} payrollId - The payroll ID to validate
     * @returns {boolean} - Whether the payroll ID is valid
     */
    function validatePayrollId(payrollId) {
        // Format: D[KBROFPSGW]-\d{6}
        // K - Kitchen, B - Bar, R - Restaurant, O - Office, F - Front of House, 
        // P - Private Events, S - Service, G - General, W - Warehouse
        const pattern = /^D[KBROFPSGW]-\d{6}$/;
        return pattern.test(payrollId);
    }
    
    /**
     * Validate password
     * @param {string} password - The password to validate
     * @returns {boolean} - Whether the password is valid
     */
    function validatePassword(password) {
        return password.length >= 8;
    }
    
    /**
     * Update form validation state
     */
    function updateFormValidation() {
        const isPayrollIdValid = validatePayrollId(payrollIdInput.value);
        const isPasswordValid = validatePassword(passwordInput.value);
        
        // Update payroll ID visual validation
        if (payrollIdInput.value) {
            if (isPayrollIdValid) {
                payrollIdInput.classList.add('valid');
                payrollIdInput.classList.remove('invalid');
                payrollIdInput.parentElement.querySelector('.valid-icon').classList.remove('hidden');
            } else {
                payrollIdInput.classList.add('invalid');
                payrollIdInput.classList.remove('valid');
                payrollIdInput.parentElement.querySelector('.valid-icon').classList.add('hidden');
            }
        } else {
            payrollIdInput.classList.remove('valid', 'invalid');
            payrollIdInput.parentElement.querySelector('.valid-icon').classList.add('hidden');
        }
        
        // Update password visual validation
        if (passwordInput.value) {
            if (isPasswordValid) {
                passwordInput.classList.add('valid');
                passwordInput.classList.remove('invalid');
                passwordInput.parentElement.querySelector('.valid-icon').classList.remove('hidden');
            } else {
                passwordInput.classList.add('invalid');
                passwordInput.classList.remove('valid');
                passwordInput.parentElement.querySelector('.valid-icon').classList.add('hidden');
            }
        } else {
            passwordInput.classList.remove('valid', 'invalid');
            passwordInput.parentElement.querySelector('.valid-icon').classList.add('hidden');
        }
        
        // Enable/disable submit button
        loginSubmitBtn.disabled = !(isPayrollIdValid && isPasswordValid);
    }
    
    // Add input event listeners for real-time validation
    payrollIdInput.addEventListener('input', updateFormValidation);
    passwordInput.addEventListener('input', updateFormValidation);
    
    // Validate form on submission
    loginForm.addEventListener('submit', async (event) => {
        // Client-side validation
        const isPayrollIdValid = validatePayrollId(payrollIdInput.value);
        const isPasswordValid = validatePassword(passwordInput.value);
        
        if (!isPayrollIdValid || !isPasswordValid) {
            event.preventDefault();
            
            // Show appropriate error message
            let errorMessage = '';
            
            if (!isPayrollIdValid) {
                errorMessage = 'Please enter a valid Payroll ID (e.g., DK-308020)';
            } else if (!isPasswordValid) {
                errorMessage = 'Password must be at least 8 characters long';
            }
            
            loginErrors.querySelector('p').textContent = errorMessage;
            loginErrors.classList.remove('hidden');
            
            return;
        }
        
        // If using AJAX for form submission (optional)
        if (false) { // Set to true to enable AJAX submission
            event.preventDefault();
            
            // Show loading overlay
            loadingOverlay.classList.remove('hidden');
            
            try {
                const formData = new FormData(loginForm);
                const response = await fetch(loginForm.action, {
                    method: 'POST',
                    headers: {
                        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                    },
                    body: formData
                });
                
                if (response.redirected) {
                    // Follow redirect
                    window.location.href = response.url;
                    return;
                }
                
                const data = await response.json();
                
                if (!response.ok) {
                    throw new Error(data.error || 'Authentication failed');
                }
                
                // Success - redirect to dashboard
                window.location.href = data.redirect || '/dashboard';
                
            } catch (error) {
                // Hide loading overlay
                loadingOverlay.classList.add('hidden');
                
                // Show error message
                loginErrors.querySelector('p').textContent = error.message || 'An error occurred during login';
                loginErrors.classList.remove('hidden');
            }
        }
    });
    
    // Initialize validation on page load
    updateFormValidation();
});

/**
 * Close a modal by ID
 * @param {string} modalId - The ID of the modal to close
 */
function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('hidden');
    }
}

/**
 * Show an error in the modal
 * @param {string} title - The error title
 * @param {string} message - The error message
 */
function showError(title, message) {
    const errorModal = document.getElementById('error-modal');
    const errorTitle = document.getElementById('error-title');
    const errorMessage = document.getElementById('error-message');
    
    errorTitle.textContent = title || 'Error';
    errorMessage.textContent = message || 'An unexpected error occurred';
    
    errorModal.classList.remove('hidden');
}
