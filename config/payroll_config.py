"""
Static payroll configuration settings that don't vary by company.
These settings define standard calculations and default values used across all companies.
Company-specific details are retrieved dynamically from MongoDB.
"""
from decimal import Decimal

# Default payment reference prefix (will be combined with company-specific details)
DEFAULT_PAYMENT_REFERENCE_PREFIX = "PAY"

# Superannuation rate (currently 11.5% in Australia as of 2023-2024)
SUPERANNUATION_RATE = Decimal('0.115')

# Standard hours
STANDARD_HOURS = {
    'weekly': Decimal('38'),
    'fortnightly': Decimal('76'),
    'monthly': Decimal('164.67')  # 38 * 52 / 12
}

# Leave entitlements (annual)
LEAVE_ENTITLEMENTS = {
    'annual_leave': {
        'hours': Decimal('152'),  # 4 weeks
        'accrual_type': 'continuous'
    },
    'sick_leave': {
        'hours': Decimal('76'),  # 2 weeks
        'accrual_type': 'continuous'
    },
    'personal_leave': {
        'hours': Decimal('38'),  # 1 week
        'accrual_type': 'continuous'
    },
    'bereavement_leave': {
        'hours': Decimal('15.2'),  # 2 days
        'accrual_type': 'continuous'
    }
}

# Map MongoDB leave field names to standard names
LEAVE_MAPPING = {
    'holiday_accrued': 'annual_leave',
    'holiday_taken': 'annual_leave_taken',
    'sick_accrued': 'sick_leave',
    'sick_taken': 'sick_leave_taken',
    'carers_accrued': 'personal_leave',
    'carers_taken': 'personal_leave_taken',
    'bereavement_accrued': 'bereavement_leave',
    'bereavement_taken': 'bereavement_leave_taken',
}

# Tax brackets (simplified Australian tax rates for 2023-2024)
TAX_BRACKETS = [
    {'threshold': Decimal('0'), 'rate': Decimal('0'), 'base': Decimal('0')},
    {'threshold': Decimal('18201'), 'rate': Decimal('0.19'), 'base': Decimal('0')},
    {'threshold': Decimal('45001'), 'rate': Decimal('0.325'), 'base': Decimal('5092')},
    {'threshold': Decimal('120001'), 'rate': Decimal('0.37'), 'base': Decimal('29467')},
    {'threshold': Decimal('180001'), 'rate': Decimal('0.45'), 'base': Decimal('51667')}
]

# Period divisors for pay frequency
PERIOD_DIVISORS = {
    'weekly': Decimal('52'),
    'fortnightly': Decimal('26'),
    'monthly': Decimal('12')
}
