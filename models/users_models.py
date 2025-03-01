"""
Module: users_models.py
Defines the BusinessUser model for the application.

This model represents a business user with detailed personal, contact, employment,
and ancillary information. It includes extended embedded documents for next of kin,
pay rates, leave entitlements, and accrued employment. The new 'role_id' field and the
'work_area_name' field have been integrated to match the updated employee dataset.

Indexes (as provided):
  - Unique index on payroll_id.
  - Compound index on venue_id and company_id.
  - Regular index on work_area_id.
  - Unique index on linking_id.
  - Compound index on suburb and post_code.
  - Regular index on role.
  - Regular index on next_of_kin.contact.
  - Collation compound index on first_name and last_name.
  - Text index on first_name, last_name, and work_email.
  - Compound index on employment_details.employment_type, employment_details.pay_type, and employment_details.pay_rate.per_annum_rate.
  - Regular index on employment_details.pay_rate.per_annum_rate.
  - Regular index on accrued_employment.salary_ytd.
  - Partial index on status.
  - Regular index on venue_id.
  - Regular index on work_area_name.
"""

import datetime
import logging
from mongoengine import (
    Document,
    EmbeddedDocument,
    EmbeddedDocumentField,
    StringField,
    EmailField,
    DateTimeField,
    FloatField,
    ListField
)

# Configure logger for this module
logger = logging.getLogger(__name__)


class NextOfKin(EmbeddedDocument):
    """
    Embedded document representing next of kin details.
    """
    name = StringField(required=True, max_length=100)
    relationship = StringField(required=True, max_length=50)
    contact = StringField(required=True, max_length=100)


class PayRate(EmbeddedDocument):
    """
    Embedded document representing pay rate details.
    Now includes fortnight_rate and monthly_rate in addition to per_annum_rate.
    """
    fortnight_rate = FloatField(required=True)
    monthly_rate = FloatField(required=True)
    per_annum_rate = FloatField(required=True)


class EmploymentDetails(EmbeddedDocument):
    """
    Embedded document for employment details.
    """
    hired_date = DateTimeField(required=True)
    employment_type = StringField(required=True, max_length=50)
    pay_type = StringField(required=True, max_length=50)
    pay_rate = EmbeddedDocumentField(PayRate, required=True)


class LeaveEntitlements(EmbeddedDocument):
    """
    Embedded document for leave entitlement details.
    """
    holiday_accrued = FloatField(required=True)
    holiday_taken = FloatField(required=True)
    sick_accrued = FloatField(required=True)
    sick_taken = FloatField(required=True)
    carers_accrued = FloatField(required=True)
    carers_taken = FloatField(required=True)
    bereavement_accrued = FloatField(required=True)
    bereavement_taken = FloatField(required=True)
    maternity_entitlement = FloatField(required=True)
    maternity_taken = FloatField(required=True)
    unpaid_leave_taken = FloatField(required=True)


class AccruedEmployment(EmbeddedDocument):
    """
    Embedded document for accrued employment details.
    """
    days_employed = FloatField(required=True)
    unpaid_leave = FloatField(required=True)
    tax_withheld = FloatField(required=True)
    salary_ytd = FloatField(required=True)
    tax_withheld_ytd = FloatField(required=True)


class BusinessUser(Document):
    """
    BusinessUser model representing a business user record.

    Fields:
      - payroll_id: Unique identifier for payroll.
      - venue_id: Identifier for the venue.
      - company_id: Identifier for the company.
      - work_area_id: Identifier for the work area.
      - work_area_name: Name of the work area (e.g., "kitchen", "venue").
      - linking_id: Unique linking identifier.
      - role_id: Unique identifier for the employee's role.
      - suburb, post_code, state, address: Location details.
      - first_name, last_name, preferred_name: Personal names.
      - date_of_birth: Date of birth.
      - personal_contact: Personal phone number.
      - next_of_kin: Embedded document with next of kin details.
      - role: Job role (display name).
      - work_email: Work email address.
      - password: Hashed password.
      - permissions: List of permissions (e.g., admin roles).
      - employment_details: Embedded document for employment info.
      - leave_entitlements: Embedded document for leave details.
      - accrued_employment: Embedded document for accrued employment metrics.
      - venue_name: Name of the venue.
      - company_name: Name of the company.
      - status: Optional field for employee status.
      - created_at: Record creation timestamp.
      - updated_at: Record update timestamp.
    """
    payroll_id = StringField(required=True, unique=True)
    venue_id = StringField(required=True)
    company_id = StringField(required=True)
    work_area_id = StringField(required=True)
    work_area_name = StringField(max_length=100)  # NEW FIELD ADDED
    linking_id = StringField(required=True, unique=True)
    role_id = StringField(required=True, max_length=50)
    suburb = StringField(required=True, max_length=100)
    post_code = StringField(required=True, max_length=20)
    state = StringField(required=True, max_length=50)
    address = StringField(required=True, max_length=200)
    first_name = StringField(required=True, max_length=50)
    last_name = StringField(required=True, max_length=50)
    preferred_name = StringField(max_length=50)
    date_of_birth = DateTimeField()
    personal_contact = StringField(max_length=20)
    next_of_kin = EmbeddedDocumentField(NextOfKin, required=True)
    role = StringField(required=True, max_length=50)
    work_email = EmailField(required=True, max_length=100)
    password = StringField(required=True)
    permissions = ListField(StringField(), default=list)
    employment_details = EmbeddedDocumentField(EmploymentDetails, required=True)
    leave_entitlements = EmbeddedDocumentField(LeaveEntitlements)
    accrued_employment = EmbeddedDocumentField(AccruedEmployment)
    venue_name = StringField(max_length=100)
    company_name = StringField(max_length=100)
    status = StringField(max_length=50)  # Optional field for employee status
    created_at = DateTimeField(default=datetime.datetime.utcnow)
    updated_at = DateTimeField(default=datetime.datetime.utcnow)

    meta = {
        'collection': 'business_users',
        'indexes': [
            {"fields": ["payroll_id"], "unique": True},
            {"fields": ["venue_id", "company_id"]},
            {"fields": ["work_area_id"]},
            {"fields": ["linking_id"], "unique": True},
            {"fields": ["suburb", "post_code"]},
            {"fields": ["role"]},
            {"fields": ["next_of_kin.contact"]},
            {"fields": ["first_name", "last_name"], "collation": {"locale": "en", "strength": 2}},
            {"fields": ["$first_name", "$last_name", "$work_email"]},
            {"fields": ["employment_details.employment_type", "employment_details.pay_type", "employment_details.pay_rate.per_annum_rate"]},
            {"fields": ["employment_details.pay_rate.per_annum_rate"]},
            {"fields": ["accrued_employment.salary_ytd"]},
            {"fields": ["status"], "partialFilterExpression": {"status": {"$exists": True}}},
            {"fields": ["venue_id"]},
            {"fields": ["work_area_name"]}  # This index now resolves correctly.
        ],
        'ordering': ['-created_at'],
    }

    def save(self, *args, **kwargs):
        """
        Overrides the default save method to update the `updated_at` timestamp.
        Logs any errors encountered during the save operation.
        """
        self.updated_at = datetime.datetime.utcnow()
        try:
            result = super(BusinessUser, self).save(*args, **kwargs)
            return result
        except Exception as e:
            logger.error("Error saving BusinessUser (%s %s): %s", self.first_name, self.last_name, str(e))
            raise
