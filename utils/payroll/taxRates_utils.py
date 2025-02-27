"""
Utility functions for calculating tax and related payroll amounts.
"""
from decimal import Decimal, ROUND_HALF_UP
from config.payroll_config import STANDARD_HOURS, SUPERANNUATION_RATE, TAX_BRACKETS, PERIOD_DIVISORS

def calculate_tax(annual_salary):
    """
    Calculate tax based on annual salary (simplified Australian tax rates for 2023-2024).
    
    Args:
        annual_salary (Decimal): Annual salary
        
    Returns:
        Decimal: Annual tax amount
    """
    # Convert to Decimal if it's not already
    if not isinstance(annual_salary, Decimal):
        annual_salary = Decimal(str(annual_salary))
    
    # Find applicable tax bracket
    applicable_bracket = TAX_BRACKETS[0]
    for bracket in TAX_BRACKETS:
        if annual_salary >= bracket['threshold']:
            applicable_bracket = bracket
        else:
            break
    
    # Calculate tax based on bracket
    if applicable_bracket['threshold'] == Decimal('0'):
        annual_tax = Decimal('0')
    else:
        annual_tax = applicable_bracket['base'] + (annual_salary - applicable_bracket['threshold'] + Decimal('1')) * applicable_bracket['rate']
    
    return annual_tax.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

def calculate_period_amounts(annual_salary, pay_frequency='fortnightly'):
    """
    Calculate various amounts for a pay period.
    
    Args:
        annual_salary (Decimal): Annual salary
        pay_frequency (str): Pay frequency ('weekly', 'fortnightly', 'monthly')
        
    Returns:
        dict: Dictionary containing period amounts
    """
    # Convert to Decimal if not already
    if not isinstance(annual_salary, Decimal):
        annual_salary = Decimal(str(annual_salary))
    
    # Get period divisor
    divisor = PERIOD_DIVISORS.get(pay_frequency, Decimal('26'))  # Default to fortnightly
    
    # Get standard hours for the period
    hours = STANDARD_HOURS.get(pay_frequency, Decimal('76'))  # Default to fortnightly
    
    # Calculate period gross
    period_gross = (annual_salary / divisor).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    
    # Calculate period tax
    annual_tax = calculate_tax(annual_salary)
    period_tax = (annual_tax / divisor).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    
    # Calculate period net
    period_net = period_gross - period_tax
    
    # Calculate superannuation
    period_super = (period_gross * SUPERANNUATION_RATE).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    
    # Calculate hourly rate
    hourly_rate = (annual_salary / (Decimal('52') * Decimal('38'))).quantize(Decimal('0.001'), rounding=ROUND_HALF_UP)
    
    return {
        'gross': period_gross,
        'tax': period_tax,
        'net': period_net,
        'super': period_super,
        'hours': hours,
        'hourly_rate': hourly_rate
    }

def calculate_ytd_amounts(period_amounts, num_periods=1):
    """
    Calculate year-to-date amounts based on period amounts.
    
    Args:
        period_amounts (dict): Dictionary of period amounts
        num_periods (int): Number of periods to include in YTD
        
    Returns:
        dict: Dictionary containing YTD amounts
    """
    return {
        'earnings': (period_amounts['gross'] * Decimal(str(num_periods))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP),
        'tax': (period_amounts['tax'] * Decimal(str(num_periods))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP),
        'super': (period_amounts['super'] * Decimal(str(num_periods))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    }

def get_user_ytd_amounts(user_data):
    """
    Get year-to-date amounts from user data.
    
    Args:
        user_data (dict): User data containing accrued employment information
        
    Returns:
        dict: Dictionary containing YTD amounts
    """
    accrued = user_data.get('accrued', {})
    
    return {
        'earnings': Decimal(str(accrued.get('salary_ytd', '0'))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP),
        'tax': Decimal(str(accrued.get('tax_withheld_ytd', '0'))).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP),
        # Estimate super YTD based on salary YTD and super rate
        'super': (Decimal(str(accrued.get('salary_ytd', '0'))) * SUPERANNUATION_RATE).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    }
