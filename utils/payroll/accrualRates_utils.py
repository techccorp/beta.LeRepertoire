"""
Utility functions for calculating leave accruals and entitlements.
"""
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, date
from config.payroll_config import LEAVE_ENTITLEMENTS, LEAVE_MAPPING

def calculate_service_period(start_date, end_date=None):
    """
    Calculate the service period in years.
    
    Args:
        start_date (str or date): Employment start date (YYYY-MM-DD)
        end_date (str or date, optional): End date for calculation (defaults to today)
        
    Returns:
        Decimal: Service period in years
    """
    # Convert string dates to date objects if needed
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    elif isinstance(start_date, dict) and '$date' in start_date:
        # Handle MongoDB date format
        start_date = datetime.fromisoformat(start_date['$date'][:-1]).date()
    
    if end_date is None:
        end_date = date.today()
    elif isinstance(end_date, str):
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
    
    # Calculate days difference and convert to years
    days_diff = (end_date - start_date).days
    years = Decimal(str(days_diff)) / Decimal('365.25')
    
    return years.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

def calculate_leave_accrual(fte, service_years, leave_type):
    """
    Calculate leave accrual based on service period and FTE.
    
    Args:
        fte (Decimal): Full-time equivalent (0.0 to 1.0)
        service_years (Decimal): Years of service
        leave_type (str): Type of leave ('annual_leave', 'sick_leave', 'personal_leave')
        
    Returns:
        Decimal: Accrued leave hours
    """
    # Get annual entitlement
    annual_hours = LEAVE_ENTITLEMENTS.get(leave_type, {}).get('hours', Decimal('0'))
    
    # Pro-rata based on FTE
    pro_rata_hours = annual_hours * fte
    
    # Accrual based on service period
    accrual_type = LEAVE_ENTITLEMENTS.get(leave_type, {}).get('accrual_type', 'continuous')
    
    if accrual_type == 'continuous':
        # Continuous accrual (pro-rata for service period)
        accrued_hours = pro_rata_hours * service_years
    else:
        # Annual grant (full amount if service period >= 1 year)
        accrued_hours = pro_rata_hours if service_years >= Decimal('1') else Decimal('0')
    
    return accrued_hours.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

def get_leave_summary(fte, start_date, annual_salary, current_balances=None):
    """
    Calculate leave summary with accruals and balances.
    
    Args:
        fte (Decimal): Full-time equivalent (0.0 to 1.0)
        start_date (str or date): Employment start date
        annual_salary (Decimal): Annual salary
        current_balances (dict, optional): Current leave balances
        
    Returns:
        dict: Leave summary with accruals and balances
    """
    # Convert to Decimal if not already
    if not isinstance(fte, Decimal):
        fte = Decimal(str(fte))
    
    if not isinstance(annual_salary, Decimal):
        annual_salary = Decimal(str(annual_salary))
    
    # Default current balances
    if current_balances is None:
        current_balances = {
            'annual_leave': Decimal('0'),
            'sick_leave': Decimal('0'),
            'personal_leave': Decimal('0'),
            'bereavement_leave': Decimal('0')
        }
    
    # Calculate service period
    service_years = calculate_service_period(start_date)
    
    # Calculate leave accruals and balances
    leave_summary = {}
    
    for leave_type in LEAVE_ENTITLEMENTS:
        accrued = calculate_leave_accrual(fte, service_years, leave_type)
        
        # Get current balance (or default to 0)
        current_balance = Decimal(str(current_balances.get(leave_type, '0')))
        
        # Calculate total balance
        total_balance = current_balance + accrued
        
        # Calculate monetary value (only for annual leave)
        hourly_rate = annual_salary / (Decimal('52') * Decimal('38'))
        monetary_value = Decimal('0')
        
        if leave_type == 'annual_leave':
            monetary_value = (total_balance * hourly_rate).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        
        leave_summary[leave_type] = {
            'accrued': accrued,
            'total': total_balance,
            'monetary_value': monetary_value
        }
    
    return leave_summary

def map_user_leave_data(user_data):
    """
    Map user leave entitlements from MongoDB format to standard format.
    
    Args:
        user_data (dict): User data containing leave entitlements
        
    Returns:
        dict: Mapped leave data in standard format
    """
    leave_data = {}
    user_leave = user_data.get('leave', {})
    
    for mongo_field, standard_field in LEAVE_MAPPING.items():
        if mongo_field in user_leave:
            leave_data[standard_field] = Decimal(str(user_leave.get(mongo_field, '0')))
    
    return leave_data

def get_user_leave_summary(user_data):
    """
    Get leave summary from user data.
    
    Args:
        user_data (dict): User data containing leave entitlements
        
    Returns:
        dict: Leave summary in the format expected by templates
    """
    leave_data = map_user_leave_data(user_data)
    
    # Format for template compatibility
    return {
        'annual': {
            'accrued': leave_data.get('annual_leave', Decimal('0')),
            'used': leave_data.get('annual_leave_taken', Decimal('0')),
            'balance': leave_data.get('annual_leave', Decimal('0')) - leave_data.get('annual_leave_taken', Decimal('0'))
        },
        'sick': {
            'accrued': leave_data.get('sick_leave', Decimal('0')),
            'used': leave_data.get('sick_leave_taken', Decimal('0')),
            'balance': leave_data.get('sick_leave', Decimal('0')) - leave_data.get('sick_leave_taken', Decimal('0'))
        },
        'personal': {
            'accrued': leave_data.get('personal_leave', Decimal('0')),
            'used': leave_data.get('personal_leave_taken', Decimal('0')),
            'balance': leave_data.get('personal_leave', Decimal('0')) - leave_data.get('personal_leave_taken', Decimal('0'))
        }
    }
