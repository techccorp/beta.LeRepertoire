/**
 * Authentication functionality for Le Repertoire
 */

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const mfaForm = document.getElementById('mfa-form');
    const payrollIdInput = document.getElementById('payroll-id');
    const passwordInput = document.getElementById('password');
    const mfaCodeInput = document.getElementById('mfa-code');
    const useRecoveryCodeCheckbox = document.getElementById('use-recovery-code');
    const loginSubmitBtn = document.getElementById('login-submit-btn');
    const mfaSubmitBtn = document.getElementById('mfa-submit-btn');
    const loginErrors = document.getElementById('login-errors');
    const mfaErrors = document.getElementById('mfa-errors');
    const loadingOverlay = document.getElementById('loading-overlay');
    const recoveryCodeLink = document.getElementById('recovery-code-link');
    const normalCodeLink = document.getElementById('normal-code-link');
    const recoveryCodeHelp = document.getElementById('recovery-code-help');
    
    let currentPayrollId = null;
    let mfaRequired = false;
    
    /**
     * Validate payroll ID format
     * @param {string} payrollId - The payroll ID to validate
     * @returns {boolean} - Whether the payroll ID is valid
     */
    function validatePayrollId(payrollId) {
        // Format: D[ABCFGHKMORSV]-\d{6}
        // A - Admin, B - Bar, C - Cleaners, F - Functions, G - Guest Services, 
        // H - House Keeping, K - Kitchen, M - Maintenance, O - Operations, 
        // R - Restaurant, S - Store Room, V - Venue
        const pattern = /^D[ABCFGHKMORSV]-\d{6}$/;
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
     * Validate MFA code
     * @param {string} code - The MFA code to validate
     * @param {boolean} isRecoveryCode - Whether this is a recovery code
     * @returns {boolean} - Whether the code is valid
     */
    function validateMfaCode(code, isRecoveryCode) {
        // TOTP codes are 6 digits
        if (!isRecoveryCode) {
            return /^\d{6}$/.test(code.replace(/\s+/g, ''));
        }
        
        // Recovery codes are 5 groups of 4 characters separated by hyphens
        // e.g. ABCD-EFGH-IJKL-MNOP-QRST
        return /^[A-Z0-9]{4}(-[A-Z0-9]{4}){4}$/.test(code.replace(/\s+/g, ''));
    }
    
    /**
     * Update form validation state
     */
    function updateFormValidation() {
        // Skip if form elements don't exist
        if (!payrollIdInput || !passwordInput || !loginSubmitBtn) {
            return;
        }
        
        const isPayrollIdValid = validatePayrollId(payrollIdInput.value);
        const isPasswordValid = validatePassword(passwordInput.value);
        
        // Update payroll ID visual validation
        if (payrollIdInput.value) {
            if (isPayrollIdValid) {
                payrollIdInput.classList.add('valid');
                payrollIdInput.classList.remove('invalid');
                const validIcon = payrollIdInput.parentElement.querySelector('.valid-icon');
                if (validIcon) validIcon.classList.remove('hidden');
            } else {
                payrollIdInput.classList.add('invalid');
                payrollIdInput.classList.remove('valid');
                const validIcon = payrollIdInput.parentElement.querySelector('.valid-icon');
                if (validIcon) validIcon.classList.add('hidden');
            }
        } else {
            payrollIdInput.classList.remove('valid', 'invalid');
            const validIcon = payrollIdInput.parentElement.querySelector('.valid-icon');
            if (validIcon) validIcon.classList.add('hidden');
        }
        
        // Update password visual validation
        if (passwordInput.value) {
            if (isPasswordValid) {
                passwordInput.classList.add('valid');
                passwordInput.classList.remove('invalid');
                const validIcon = passwordInput.parentElement.querySelector('.valid-icon');
                if (validIcon) validIcon.classList.remove('hidden');
            } else {
                passwordInput.classList.add('invalid');
                passwordInput.classList.remove('valid');
                const validIcon = passwordInput.parentElement.querySelector('.valid-icon');
                if (validIcon) validIcon.classList.add('hidden');
            }
        } else {
            passwordInput.classList.remove('valid', 'invalid');
            const validIcon = passwordInput.parentElement.querySelector('.valid-icon');
            if (validIcon) validIcon.classList.add('hidden');
        }
        
        // Enable/disable submit button
        if (loginSubmitBtn) {
            loginSubmitBtn.disabled = !(isPayrollIdValid && isPasswordValid);
        }
    }
    
    /**
     * Update MFA form validation state
     */
    function updateMfaFormValidation() {
        // Skip if form elements don't exist
        if (!mfaCodeInput || !mfaSubmitBtn) {
            return;
        }
        
        const isRecoveryCode = useRecoveryCodeCheckbox && useRecoveryCodeCheckbox.checked;
        const isMfaCodeValid = validateMfaCode(mfaCodeInput.value, isRecoveryCode);
        
        // Update MFA code visual validation
        if (mfaCodeInput.value) {
            if (isMfaCodeValid) {
                mfaCodeInput.classList.add('valid');
                mfaCodeInput.classList.remove('invalid');
                const validIcon = mfaCodeInput.parentElement.querySelector('.valid-icon');
                if (validIcon) validIcon.classList.remove('hidden');
            } else {
                mfaCodeInput.classList.add('invalid');
                mfaCodeInput.classList.remove('valid');
                const validIcon = mfaCodeInput.parentElement.querySelector('.valid-icon');
                if (validIcon) validIcon.classList.add('hidden');
            }
        } else {
            mfaCodeInput.classList.remove('valid', 'invalid');
            const validIcon = mfaCodeInput.parentElement.querySelector('.valid-icon');
            if (validIcon) validIcon.classList.add('hidden');
        }
        
        // Enable/disable submit button
        if (mfaSubmitBtn) {
            mfaSubmitBtn.disabled = !isMfaCodeValid;
        }
    }
    
    /**
     * Show MFA form and hide login form
     */
    function showMfaForm() {
        if (loginForm && mfaForm) {
            loginForm.classList.add('hidden');
            mfaForm.classList.remove('hidden');
            
            // Update recovery code help text visibility
            toggleRecoveryCodeHelp();
            
            // Focus on MFA code input
            if (mfaCodeInput) {
                mfaCodeInput.focus();
            }
        }
    }
    
    /**
     * Show login form and hide MFA form
     */
    function showLoginForm() {
        if (loginForm && mfaForm) {
            mfaForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
            
            // Reset MFA related state
            mfaRequired = false;
            currentPayrollId = null;
            
            // Clear MFA code input
            if (mfaCodeInput) {
                mfaCodeInput.value = '';
            }
            
            // Reset to normal code mode
            if (useRecoveryCodeCheckbox) {
                useRecoveryCodeCheckbox.checked = false;
            }
        }
    }
    
    /**
     * Toggle recovery code help text based on checkbox state
     */
    function toggleRecoveryCodeHelp() {
        if (useRecoveryCodeCheckbox && recoveryCodeHelp) {
            if (useRecoveryCodeCheckbox.checked) {
                recoveryCodeHelp.classList.remove('hidden');
                mfaCodeInput.placeholder = 'Recovery Code (e.g., ABCD-EFGH-IJKL-MNOP-QRST)';
            } else {
                recoveryCodeHelp.classList.add('hidden');
                mfaCodeInput.placeholder = 'Authentication Code (6 digits)';
            }
        }
    }
    
    // Add input event listeners for real-time validation
    if (payrollIdInput) payrollIdInput.addEventListener('input', updateFormValidation);
    if (passwordInput) passwordInput.addEventListener('input', updateFormValidation);
    if (mfaCodeInput) mfaCodeInput.addEventListener('input', updateMfaFormValidation);
    if (useRecoveryCodeCheckbox) {
        useRecoveryCodeCheckbox.addEventListener('change', () => {
            updateMfaFormValidation();
            toggleRecoveryCodeHelp();
        });
    }
    
    // Add link event listeners for toggling between recovery and normal code
    if (recoveryCodeLink) {
        recoveryCodeLink.addEventListener('click', (e) => {
            e.preventDefault();
            if (useRecoveryCodeCheckbox) {
                useRecoveryCodeCheckbox.checked = true;
                toggleRecoveryCodeHelp();
                updateMfaFormValidation();
            }
        });
    }
    
    if (normalCodeLink) {
        normalCodeLink.addEventListener('click', (e) => {
            e.preventDefault();
            if (useRecoveryCodeCheckbox) {
                useRecoveryCodeCheckbox.checked = false;
                toggleRecoveryCodeHelp();
                updateMfaFormValidation();
            }
        });
    }
    
    // Validate form on submission
    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            
            // Client-side validation
            const isPayrollIdValid = validatePayrollId(payrollIdInput.value);
            const isPasswordValid = validatePassword(passwordInput.value);
            
            if (!isPayrollIdValid || !isPasswordValid) {
                // Show appropriate error message
                let errorMessage = '';
                
                if (!isPayrollIdValid) {
                    errorMessage = 'Please enter a valid Payroll ID (e.g., DK-308020)';
                } else if (!isPasswordValid) {
                    errorMessage = 'Password must be at least 8 characters long';
                }
                
                if (loginErrors) {
                    const errorParagraph = loginErrors.querySelector('p');
                    if (errorParagraph) {
                        errorParagraph.textContent = errorMessage;
                        loginErrors.classList.remove('hidden');
                    }
                }
                
                return;
            }
            
            // Show loading overlay
            if (loadingOverlay) loadingOverlay.classList.remove('hidden');
            
            try {
                // Get form data
                const payrollId = payrollIdInput.value;
                const password = passwordInput.value;
                
                // Store payroll ID for MFA step
                currentPayrollId = payrollId;
                
                // Make login request
                const response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
                    },
                    body: JSON.stringify({ payroll_id: payrollId, password: password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Success - check if MFA is required
                    if (data.mfa_required) {
                        // Hide loading overlay
                        if (loadingOverlay) loadingOverlay.classList.add('hidden');
                        
                        // Set MFA required flag
                        mfaRequired = true;
                        
                        // Show MFA form
                        showMfaForm();
                    } else {
                        // No MFA required - redirect to dashboard
                        window.location.href = data.redirect || '/dashboard';
                    }
                } else {
                    // Hide loading overlay
                    if (loadingOverlay) loadingOverlay.classList.add('hidden');
                    
                    // Show error message
                    let errorMessage = data.message || 'Authentication failed';
                    
                    if (loginErrors) {
                        const errorParagraph = loginErrors.querySelector('p');
                        if (errorParagraph) {
                            errorParagraph.textContent = errorMessage;
                            loginErrors.classList.remove('hidden');
                        }
                    }
                }
                
            } catch (error) {
                // Hide loading overlay
                if (loadingOverlay) loadingOverlay.classList.add('hidden');
                
                // Show error message
                let errorMessage = 'An error occurred during login';
                if (error.message) {
                    errorMessage = error.message;
                }
                
                if (loginErrors) {
                    const errorParagraph = loginErrors.querySelector('p');
                    if (errorParagraph) {
                        errorParagraph.textContent = errorMessage;
                        loginErrors.classList.remove('hidden');
                    }
                }
                
                console.error('Login error:', error);
            }
        });
    }
    
    // Handle MFA form submission
    if (mfaForm) {
        mfaForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            
            // Client-side validation
            const isRecoveryCode = useRecoveryCodeCheckbox && useRecoveryCodeCheckbox.checked;
            const isMfaCodeValid = validateMfaCode(mfaCodeInput.value, isRecoveryCode);
            
            if (!isMfaCodeValid) {
                // Show error message
                let errorMessage = isRecoveryCode
                    ? 'Please enter a valid recovery code'
                    : 'Please enter a valid 6-digit authentication code';
                
                if (mfaErrors) {
                    const errorParagraph = mfaErrors.querySelector('p');
                    if (errorParagraph) {
                        errorParagraph.textContent = errorMessage;
                        mfaErrors.classList.remove('hidden');
                    }
                }
                
                return;
            }
            
            // Show loading overlay
            if (loadingOverlay) loadingOverlay.classList.remove('hidden');
            
            try {
                // Make MFA authentication request
                const response = await fetch('/auth/mfa/authenticate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
                    },
                    body: JSON.stringify({
                        payroll_id: currentPayrollId,
                        code: mfaCodeInput.value,
                        use_recovery_code: isRecoveryCode
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    // Success - redirect to dashboard
                    window.location.href = data.redirect || '/dashboard';
                } else {
                    // Hide loading overlay
                    if (loadingOverlay) loadingOverlay.classList.add('hidden');
                    
                    // Show error message
                    let errorMessage = data.message || 'MFA authentication failed';
                    
                    if (mfaErrors) {
                        const errorParagraph = mfaErrors.querySelector('p');
                        if (errorParagraph) {
                            errorParagraph.textContent = errorMessage;
                            mfaErrors.classList.remove('hidden');
                        }
                    }
                }
                
            } catch (error) {
                // Hide loading overlay
                if (loadingOverlay) loadingOverlay.classList.add('hidden');
                
                // Show error message
                let errorMessage = 'An error occurred during MFA authentication';
                if (error.message) {
                    errorMessage = error.message;
                }
                
                if (mfaErrors) {
                    const errorParagraph = mfaErrors.querySelector('p');
                    if (errorParagraph) {
                        errorParagraph.textContent = errorMessage;
                        mfaErrors.classList.remove('hidden');
                    }
                }
                
                console.error('MFA authentication error:', error);
            }
        });
    }
    
    // Add back button to return to login form
    const backToLoginButton = document.getElementById('back-to-login');
    if (backToLoginButton) {
        backToLoginButton.addEventListener('click', (event) => {
            event.preventDefault();
            showLoginForm();
        });
    }
    
    // Initialize validation on page load
    updateFormValidation();
    updateMfaFormValidation();
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
    
    if (errorModal && errorTitle && errorMessage) {
        errorTitle.textContent = title || 'Error';
        errorMessage.textContent = message || 'An unexpected error occurred';
        
        errorModal.classList.remove('hidden');
    } else {
        // Fallback to alert if modal elements don't exist
        alert(`${title || 'Error'}: ${message || 'An unexpected error occurred'}`);
    }
}
