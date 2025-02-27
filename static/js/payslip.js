/**
 * Payslip functionality for Le Repertoire payroll system
 * 
 * Handles:
 * - Payslip form submission
 * - Salary calculations
 * - Tax calculations
 * - Leave accrual display
 * - Payslip rendering
 */

document.addEventListener('DOMContentLoaded', function() {
    const payslipForm = document.getElementById('payslipForm');
    const payslipOutput = document.getElementById('payslipOutput');
    const annualSalaryInput = document.getElementById('annualSalary');
    const payFrequencySelect = document.getElementById('payFrequency');
    
    /**
     * Initialize the payslip form
     */
    function initPayslipForm() {
        if (!payslipForm) return;
        
        // Handle form submission
        payslipForm.addEventListener('submit', submitPayslipForm);
        
        // Setup real-time calculations for salary
        if (annualSalaryInput && payFrequencySelect) {
            [annualSalaryInput, payFrequencySelect].forEach(el => {
                el.addEventListener('input', updateSalaryCalculations);
                el.addEventListener('change', updateSalaryCalculations);
            });
            
            // Initialize calculations
            updateSalaryCalculations();
        }
    }
    
    /**
     * Submit the payslip form via AJAX
     * @param {Event} event - Form submission event
     */
    async function submitPayslipForm(event) {
        event.preventDefault();
        
        // Show loading state
        payslipForm.classList.add('opacity-50', 'pointer-events-none');
        payslipOutput.innerHTML = `
            <div class="h-full flex items-center justify-center">
                <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-amber-600"></div>
            </div>
        `;
        
        try {
            // Prepare form data
            const formData = new FormData(payslipForm);
            const data = Object.fromEntries(formData.entries());
            
            // Send request
            const response = await fetch('/payroll/generate_payslip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''
                },
                body: JSON.stringify(data)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}: ${await response.text()}`);
            }
            
            // Get HTML response
            const payslipHtml = await response.text();
            
            // Update output container
            payslipOutput.innerHTML = payslipHtml;
            
            // Initialize print button if present
            const printButton = document.getElementById('printPayslip');
            if (printButton) {
                printButton.addEventListener('click', printPayslip);
            }
            
            // Show success notification
            if (window.LeRepertoire && window.LeRepertoire.showNotification) {
                window.LeRepertoire.showNotification('Payslip generated successfully', 'success');
            }
            
        } catch (error) {
            console.error('Error generating payslip:', error);
            
            let errorMessage = 'An error occurred while generating the payslip.';
            if (error.message) {
                errorMessage = error.message;
            }
            
            payslipOutput.innerHTML = `
                <div class="p-4 bg-red-100 border border-red-400 text-red-700 rounded">
                    <p class="font-bold">Error</p>
                    <p>${errorMessage}</p>
                </div>
            `;
            
            // Show error notification
            if (window.LeRepertoire && window.LeRepertoire.showNotification) {
                window.LeRepertoire.showNotification('Error generating payslip', 'error');
            }
        } finally {
            // Reset form state
            payslipForm.classList.remove('opacity-50', 'pointer-events-none');
        }
    }
    
    /**
     * Update salary calculations in real-time as user inputs data
     */
    function updateSalaryCalculations() {
        if (!annualSalaryInput || !payFrequencySelect) return;
        
        const annualSalary = parseFloat(annualSalaryInput.value) || 0;
        const payFrequency = payFrequencySelect.value;
        
        // Calculate period amounts
        const periodAmounts = calculatePeriodAmounts(annualSalary, payFrequency);
        
        // Update display fields if they exist
        const fields = {
            'grossPay': periodAmounts.gross,
            'taxAmount': periodAmounts.tax,
            'netPay': periodAmounts.net,
            'superAmount': periodAmounts.super
        };
        
        Object.entries(fields).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = formatCurrency(value);
            }
        });
    }
    
    /**
     * Calculate pay period amounts
     * @param {number} annualSalary - Annual salary
     * @param {string} payFrequency - Pay frequency (weekly, fortnightly, monthly)
     * @returns {Object} - Calculated amounts
     */
    function calculatePeriodAmounts(annualSalary, payFrequency) {
        // Period divisors
        const divisors = {
            'weekly': 52,
            'fortnightly': 26,
            'monthly': 12
        };
        
        const divisor = divisors[payFrequency] || 26; // Default to fortnightly
        
        // Calculate gross pay
        const gross = annualSalary / divisor;
        
        // Estimate tax (simplified calculation)
        let tax = 0;
        if (annualSalary <= 18200) {
            tax = 0;
        } else if (annualSalary <= 45000) {
            tax = (annualSalary - 18200) * 0.19 / divisor;
        } else if (annualSalary <= 120000) {
            tax = (5092 + (annualSalary - 45000) * 0.325) / divisor;
        } else if (annualSalary <= 180000) {
            tax = (29467 + (annualSalary - 120000) * 0.37) / divisor;
        } else {
            tax = (51667 + (annualSalary - 180000) * 0.45) / divisor;
        }
        
        // Calculate net pay
        const net = gross - tax;
        
        // Calculate super (11.5% as of 2023-2024)
        const superAmount = gross * 0.115;
        
        return {
            gross: gross,
            tax: tax,
            net: net,
            super: superAmount
        };
    }
    
    /**
     * Format currency value
     * @param {number} value - Value to format
     * @returns {string} - Formatted currency string
     */
    function formatCurrency(value) {
        return new Intl.NumberFormat('en-AU', {
            style: 'currency',
            currency: 'AUD'
        }).format(value);
    }
    
    /**
     * Print the current payslip
     */
    function printPayslip() {
        window.print();
    }
    
    // Initialize payslip functionality
    initPayslipForm();
    
    // Export functions for testing or external use
    window.PayslipModule = {
        calculatePeriodAmounts,
        formatCurrency,
        updateSalaryCalculations,
        printPayslip
    };
});
