"""
Payment processing utilities for handling payments and refunds.
Provides standardized functions for payment operations across different providers.
"""
import json
import logging
import uuid
from datetime import datetime
from flask import current_app, g
from bson.objectid import ObjectId

logger = logging.getLogger(__name__)

# Payment status constants
PAYMENT_STATUS_PENDING = 'pending'
PAYMENT_STATUS_PROCESSING = 'processing'
PAYMENT_STATUS_COMPLETED = 'completed'
PAYMENT_STATUS_FAILED = 'failed'
PAYMENT_STATUS_REFUNDED = 'refunded'
PAYMENT_STATUS_PARTIAL_REFUND = 'partial_refund'
PAYMENT_STATUS_CANCELLED = 'cancelled'

# Payment error codes
PAYMENT_ERROR_INVALID_CARD = 'invalid_card'
PAYMENT_ERROR_INSUFFICIENT_FUNDS = 'insufficient_funds'
PAYMENT_ERROR_PAYMENT_DECLINED = 'payment_declined'
PAYMENT_ERROR_EXPIRED_CARD = 'expired_card'
PAYMENT_ERROR_PROCESSING_ERROR = 'processing_error'
PAYMENT_ERROR_INVALID_AMOUNT = 'invalid_amount'
PAYMENT_ERROR_CURRENCY_NOT_SUPPORTED = 'currency_not_supported'
PAYMENT_ERROR_DUPLICATE_TRANSACTION = 'duplicate_transaction'

def get_payment_db():
    """
    Get the MongoDB collection for payment data.
    
    Returns:
        MongoDB collection or None if not configured
    """
    if hasattr(current_app, 'mongo') and hasattr(current_app.mongo, 'db'):
        return current_app.mongo.db.payments
    return None

def get_payment_provider():
    """
    Get configured payment provider client.
    
    Returns:
        Payment provider client or None if not configured
    """
    if hasattr(current_app, 'config') and 'PAYMENT_PROVIDER' in current_app.config:
        provider_name = current_app.config['PAYMENT_PROVIDER']
        
        # Return appropriate provider based on configuration
        if provider_name == 'stripe' and hasattr(current_app, 'stripe'):
            return current_app.stripe
        elif provider_name == 'paypal' and hasattr(current_app, 'paypal'):
            return current_app.paypal
        # Add more providers as needed
    
    logger.debug("No payment provider configured")
    return None

def validate_payment_info(payment_info):
    """
    Validate payment information before processing.
    
    Args:
        payment_info (dict): Payment information to validate
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    # Ensure required fields are present
    required_fields = ['amount', 'currency', 'payment_method']
    for field in required_fields:
        if field not in payment_info or not payment_info[field]:
            return False, f"Missing required field: {field}"
    
    # Validate amount
    try:
        amount = float(payment_info['amount'])
        if amount <= 0:
            return False, "Amount must be greater than zero"
    except (ValueError, TypeError):
        return False, "Invalid amount format"
    
    # Validate currency
    currency = payment_info.get('currency', '').upper()
    supported_currencies = current_app.config.get('SUPPORTED_CURRENCIES', ['USD', 'EUR', 'GBP'])
    if currency not in supported_currencies:
        return False, f"Currency not supported: {currency}"
    
    # Validate payment method based on type
    payment_method = payment_info.get('payment_method', {})
    if isinstance(payment_method, dict):
        method_type = payment_method.get('type')
        
        if method_type == 'card':
            # Validate card details
            if 'card_number' not in payment_method:
                return False, "Missing card number"
            
            # Basic Luhn algorithm check for card number
            if not is_valid_card_number(payment_method.get('card_number', '')):
                return False, "Invalid card number"
            
            # Validate expiry date
            if 'expiry_month' not in payment_method or 'expiry_year' not in payment_method:
                return False, "Missing card expiry date"
            
            try:
                expiry_month = int(payment_method['expiry_month'])
                expiry_year = int(payment_method['expiry_year'])
                
                if expiry_month < 1 or expiry_month > 12:
                    return False, "Invalid expiry month"
                
                current_year = datetime.now().year
                if expiry_year < current_year or expiry_year > current_year + 20:
                    return False, "Invalid expiry year"
                
                # Check if card is expired
                current_month = datetime.now().month
                if expiry_year == current_year and expiry_month < current_month:
                    return False, "Card has expired"
            except (ValueError, TypeError):
                return False, "Invalid expiry date format"
                
        elif method_type == 'bank_account':
            # Validate bank account details
            if 'account_number' not in payment_method:
                return False, "Missing bank account number"
            
            if 'routing_number' not in payment_method:
                return False, "Missing routing number"
            
        elif method_type == 'wallet':
            # Validate digital wallet details
            if 'wallet_type' not in payment_method:
                return False, "Missing wallet type"
            
            supported_wallets = ['apple_pay', 'google_pay', 'paypal']
            if payment_method.get('wallet_type') not in supported_wallets:
                return False, "Unsupported wallet type"
            
        else:
            return False, f"Unsupported payment method type: {method_type}"
    else:
        return False, "Invalid payment method format"
    
    # All validations passed
    return True, ""

def is_valid_card_number(card_number):
    """
    Validate a card number using the Luhn algorithm.
    
    Args:
        card_number (str): Card number to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Remove spaces and non-digit characters
    card_number = ''.join(c for c in card_number if c.isdigit())
    
    if not card_number or not card_number.isdigit():
        return False
    
    # Check length (most card types are 13-19 digits)
    if len(card_number) < 13 or len(card_number) > 19:
        return False
    
    # Luhn algorithm
    sum_digits = 0
    reverse = card_number[::-1]
    
    for i, digit in enumerate(reverse):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        sum_digits += n
    
    return sum_digits % 10 == 0

def process_payment(payment_info, metadata=None):
    """
    Process a payment using the configured payment provider.
    
    Args:
        payment_info (dict): Payment information including amount, currency, and payment method
        metadata (dict, optional): Additional metadata for the payment. Defaults to None.
        
    Returns:
        dict: Payment result including status, transaction ID, and any error messages
    """
    payment_db = get_payment_db()
    payment_provider = get_payment_provider()
    
    if not payment_db:
        logger.error("Payment database not configured")
        return {
            'success': False,
            'status': PAYMENT_STATUS_FAILED,
            'error': 'Payment system not properly configured',
            'error_code': PAYMENT_ERROR_PROCESSING_ERROR
        }
    
    # Generate a unique payment ID
    payment_id = str(uuid.uuid4())
    
    try:
        # Validate payment information
        is_valid, error_message = validate_payment_info(payment_info)
        if not is_valid:
            logger.error(f"Invalid payment information: {error_message}")
            
            # Record failed payment attempt
            payment_record = {
                'payment_id': payment_id,
                'amount': payment_info.get('amount'),
                'currency': payment_info.get('currency'),
                'status': PAYMENT_STATUS_FAILED,
                'error': error_message,
                'error_code': PAYMENT_ERROR_INVALID_AMOUNT,
                'created_at': datetime.utcnow(),
                'updated_at': datetime.utcnow(),
                'metadata': metadata or {}
            }
            
            payment_db.insert_one(payment_record)
            
            return {
                'success': False,
                'payment_id': payment_id,
                'status': PAYMENT_STATUS_FAILED,
                'error': error_message,
                'error_code': PAYMENT_ERROR_INVALID_AMOUNT
            }
        
        # Create initial payment record
        payment_record = {
            'payment_id': payment_id,
            'amount': float(payment_info['amount']),
            'currency': payment_info['currency'].upper(),
            'payment_method': payment_info['payment_method'],
            'status': PAYMENT_STATUS_PENDING,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'user_id': g.user.id if hasattr(g, 'user') and hasattr(g.user, 'id') else None,
            'metadata': metadata or {}
        }
        
        payment_db.insert_one(payment_record)
        
        # If we're in test mode or no provider is configured, simulate payment
        if not payment_provider or current_app.config.get('PAYMENT_TEST_MODE', False):
            test_result = simulate_payment(payment_info)
            
            # Update payment record with test result
            payment_db.update_one(
                {'payment_id': payment_id},
                {'$set': {
                    'status': test_result['status'],
                    'transaction_id': test_result.get('transaction_id'),
                    'error': test_result.get('error'),
                    'error_code': test_result.get('error_code'),
                    'provider_response': test_result.get('provider_response'),
                    'updated_at': datetime.utcnow()
                }}
            )
            
            test_result['payment_id'] = payment_id
            return test_result
        
        # Process payment with the actual provider
        provider_name = current_app.config.get('PAYMENT_PROVIDER')
        logger.info(f"Processing payment via {provider_name}")
        
        provider_result = None
        
        # Route to appropriate provider-specific processing
        if provider_name == 'stripe':
            provider_result = process_stripe_payment(payment_provider, payment_info, payment_id)
        elif provider_name == 'paypal':
            provider_result = process_paypal_payment(payment_provider, payment_info, payment_id)
        else:
            provider_result = {
                'success': False,
                'status': PAYMENT_STATUS_FAILED,
                'error': f"Unsupported payment provider: {provider_name}",
                'error_code': PAYMENT_ERROR_PROCESSING_ERROR
            }
        
        # Update payment record with provider result
        payment_db.update_one(
            {'payment_id': payment_id},
            {'$set': {
                'status': provider_result['status'],
                'transaction_id': provider_result.get('transaction_id'),
                'error': provider_result.get('error'),
                'error_code': provider_result.get('error_code'),
                'provider_response': provider_result.get('provider_response'),
                'updated_at': datetime.utcnow()
            }}
        )
        
        provider_result['payment_id'] = payment_id
        return provider_result
        
    except Exception as e:
        logger.error(f"Payment processing error: {str(e)}")
        
        # Update payment record with error
        try:
            payment_db.update_one(
                {'payment_id': payment_id},
                {'$set': {
                    'status': PAYMENT_STATUS_FAILED,
                    'error': str(e),
                    'error_code': PAYMENT_ERROR_PROCESSING_ERROR,
                    'updated_at': datetime.utcnow()
                }}
            )
        except Exception as db_error:
            logger.error(f"Failed to update payment record: {str(db_error)}")
        
        return {
            'success': False,
            'payment_id': payment_id,
            'status': PAYMENT_STATUS_FAILED,
            'error': str(e),
            'error_code': PAYMENT_ERROR_PROCESSING_ERROR
        }

def simulate_payment(payment_info):
    """
    Simulate a payment for testing purposes.
    
    Args:
        payment_info (dict): Payment information
        
    Returns:
        dict: Simulated payment result
    """
    # Simple test logic - approve most payments, decline some based on amount
    amount = float(payment_info.get('amount', 0))
    
    # Generate a consistent test transaction ID
    test_transaction_id = f"test_{uuid.uuid4()}"
    
    # Simulate a declined payment for specific test amounts
    if amount == 99.99:
        return {
            'success': False,
            'status': PAYMENT_STATUS_FAILED,
            'transaction_id': test_transaction_id,
            'error': 'Payment declined (test mode)',
            'error_code': PAYMENT_ERROR_PAYMENT_DECLINED,
            'provider_response': {
                'test': True,
                'decline_reason': 'test_decline'
            }
        }
    elif amount == 55.55:
        return {
            'success': False,
            'status': PAYMENT_STATUS_FAILED,
            'transaction_id': test_transaction_id,
            'error': 'Insufficient funds (test mode)',
            'error_code': PAYMENT_ERROR_INSUFFICIENT_FUNDS,
            'provider_response': {
                'test': True,
                'decline_reason': 'insufficient_funds'
            }
        }
    
    # Simulate a successful payment
    return {
        'success': True,
        'status': PAYMENT_STATUS_COMPLETED,
        'transaction_id': test_transaction_id,
        'provider_response': {
            'test': True,
            'approval_code': 'test_approval_123'
        }
    }

def process_stripe_payment(stripe_client, payment_info, payment_id):
    """
    Process a payment via Stripe.
    
    Args:
        stripe_client: Stripe client
        payment_info (dict): Payment information
        payment_id (str): Payment ID
        
    Returns:
        dict: Payment result
    """
    # This is a placeholder for actual Stripe integration
    # In a real implementation, this would use the stripe-python SDK
    
    logger.info("Stripe payment processing is not fully implemented")
    
    # Simulate Stripe payment for now
    return simulate_payment(payment_info)

def process_paypal_payment(paypal_client, payment_info, payment_id):
    """
    Process a payment via PayPal.
    
    Args:
        paypal_client: PayPal client
        payment_info (dict): Payment information
        payment_id (str): Payment ID
        
    Returns:
        dict: Payment result
    """
    # This is a placeholder for actual PayPal integration
    # In a real implementation, this would use the paypal-python SDK
    
    logger.info("PayPal payment processing is not fully implemented")
    
    # Simulate PayPal payment for now
    return simulate_payment(payment_info)

def get_payment_status(payment_id):
    """
    Get the status of a payment.
    
    Args:
        payment_id (str): Payment ID
        
    Returns:
        dict: Payment status information or None if not found
    """
    payment_db = get_payment_db()
    if not payment_db:
        logger.error("Payment database not configured")
        return None
    
    try:
        # Find payment record
        payment = payment_db.find_one({'payment_id': payment_id})
        
        if not payment:
            logger.warning(f"Payment not found: {payment_id}")
            return None
        
        # Format payment status response
        return {
            'payment_id': payment_id,
            'status': payment.get('status'),
            'amount': payment.get('amount'),
            'currency': payment.get('currency'),
            'transaction_id': payment.get('transaction_id'),
            'created_at': payment.get('created_at'),
            'updated_at': payment.get('updated_at'),
            'error': payment.get('error'),
            'error_code': payment.get('error_code')
        }
    except Exception as e:
        logger.error(f"Error getting payment status: {str(e)}")
        return None

def refund_payment(payment_id, amount=None, reason=None):
    """
    Refund a payment, either partially or in full.
    
    Args:
        payment_id (str): Payment ID to refund
        amount (float, optional): Amount to refund. If None, full refund. Defaults to None.
        reason (str, optional): Reason for refund. Defaults to None.
        
    Returns:
        dict: Refund result including status and any error messages
    """
    payment_db = get_payment_db()
    payment_provider = get_payment_provider()
    
    if not payment_db:
        logger.error("Payment database not configured")
        return {
            'success': False,
            'error': 'Payment system not properly configured'
        }
    
    try:
        # Find payment record
        payment = payment_db.find_one({'payment_id': payment_id})
        
        if not payment:
            logger.warning(f"Payment not found for refund: {payment_id}")
            return {
                'success': False,
                'error': 'Payment not found'
            }
        
        # Check if payment is in a refundable state
        if payment.get('status') != PAYMENT_STATUS_COMPLETED:
            logger.warning(f"Payment cannot be refunded, status: {payment.get('status')}")
            return {
                'success': False,
                'error': f"Payment cannot be refunded, status: {payment.get('status')}"
            }
        
        # Determine refund amount
        original_amount = float(payment.get('amount', 0))
        refund_amount = amount if amount is not None else original_amount
        
        # Validate refund amount
        if refund_amount <= 0 or refund_amount > original_amount:
            return {
                'success': False,
                'error': 'Invalid refund amount'
            }
        
        # Generate a unique refund ID
        refund_id = str(uuid.uuid4())
        
        # Create initial refund record
        refund_record = {
            'refund_id': refund_id,
            'payment_id': payment_id,
            'transaction_id': payment.get('transaction_id'),
            'amount': refund_amount,
            'currency': payment.get('currency'),
            'reason': reason,
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'user_id': g.user.id if hasattr(g, 'user') and hasattr(g.user, 'id') else None
        }
        
        payment_db.insert_one(refund_record)
        
        # If we're in test mode or no provider is configured, simulate refund
        if not payment_provider or current_app.config.get('PAYMENT_TEST_MODE', False):
            test_result = simulate_refund(payment, refund_amount)
            
            # Update refund record with test result
            payment_db.update_one(
                {'refund_id': refund_id},
                {'$set': {
                    'status': test_result['status'],
                    'provider_refund_id': test_result.get('provider_refund_id'),
                    'error': test_result.get('error'),
                    'provider_response': test_result.get('provider_response'),
                    'updated_at': datetime.utcnow()
                }}
            )
            
            # Update payment status
            new_payment_status = PAYMENT_STATUS_REFUNDED if refund_amount >= original_amount else PAYMENT_STATUS_PARTIAL_REFUND
            payment_db.update_one(
                {'payment_id': payment_id},
                {'$set': {
                    'status': new_payment_status,
                    'refunded_amount': refund_amount,
                    'updated_at': datetime.utcnow()
                }}
            )
            
            test_result['refund_id'] = refund_id
            return test_result
        
        # Process refund with the actual provider
        provider_name = current_app.config.get('PAYMENT_PROVIDER')
        logger.info(f"Processing refund via {provider_name}")
        
        provider_result = None
        
        # Route to appropriate provider-specific processing
        if provider_name == 'stripe':
            provider_result = process_stripe_refund(payment_provider, payment, refund_amount, reason)
        elif provider_name == 'paypal':
            provider_result = process_paypal_refund(payment_provider, payment, refund_amount, reason)
        else:
            provider_result = {
                'success': False,
                'status': 'failed',
                'error': f"Unsupported payment provider: {provider_name}"
            }
        
        # Update refund record with provider result
        payment_db.update_one(
            {'refund_id': refund_id},
            {'$set': {
                'status': provider_result['status'],
                'provider_refund_id': provider_result.get('provider_refund_id'),
                'error': provider_result.get('error'),
                'provider_response': provider_result.get('provider_response'),
                'updated_at': datetime.utcnow()
            }}
        )
        
        # Update payment status if refund was successful
        if provider_result['success']:
            new_payment_status = PAYMENT_STATUS_REFUNDED if refund_amount >= original_amount else PAYMENT_STATUS_PARTIAL_REFUND
            payment_db.update_one(
                {'payment_id': payment_id},
                {'$set': {
                    'status': new_payment_status,
                    'refunded_amount': refund_amount,
                    'updated_at': datetime.utcnow()
                }}
            )
        
        provider_result['refund_id'] = refund_id
        return provider_result
        
    except Exception as e:
        logger.error(f"Refund processing error: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def simulate_refund(payment, refund_amount):
    """
    Simulate a refund for testing purposes.
    
    Args:
        payment (dict): Original payment record
        refund_amount (float): Amount to refund
        
    Returns:
        dict: Simulated refund result
    """
    # Generate a test refund ID
    test_refund_id = f"test_refund_{uuid.uuid4()}"
    
    # Simple test logic - approve all refunds
    return {
        'success': True,
        'status': 'completed',
        'provider_refund_id': test_refund_id,
        'provider_response': {
            'test': True,
            'approval_code': 'test_refund_approval_123'
        }
    }

def process_stripe_refund(stripe_client, payment, refund_amount, reason):
    """
    Process a refund via Stripe.
    
    Args:
        stripe_client: Stripe client
        payment (dict): Payment record
        refund_amount (float): Amount to refund
        reason (str): Reason for refund
        
    Returns:
        dict: Refund result
    """
    # This is a placeholder for actual Stripe integration
    logger.info("Stripe refund processing is not fully implemented")
    
    # Simulate Stripe refund for now
    return simulate_refund(payment, refund_amount)

def process_paypal_refund(paypal_client, payment, refund_amount, reason):
    """
    Process a refund via PayPal.
    
    Args:
        paypal_client: PayPal client
        payment (dict): Payment record
        refund_amount (float): Amount to refund
        reason (str): Reason for refund
        
    Returns:
        dict: Refund result
    """
    # This is a placeholder for actual PayPal integration
    logger.info("PayPal refund processing is not fully implemented")
    
    # Simulate PayPal refund for now
    return simulate_refund(payment, refund_amount)

def create_payment_intent(payment_info, metadata=None):
    """
    Create a payment intent for client-side payment processing.
    
    Args:
        payment_info (dict): Payment information including amount and currency
        metadata (dict, optional): Additional metadata for the payment. Defaults to None.
        
    Returns:
        dict: Payment intent information including client secret
    """
    payment_db = get_payment_db()
    payment_provider = get_payment_provider()
    
    if not payment_db:
        logger.error("Payment database not configured")
        return {
            'success': False,
            'error': 'Payment system not properly configured'
        }
    
    # Validate basic payment info
    if 'amount' not in payment_info or 'currency' not in payment_info:
        return {
            'success': False,
            'error': 'Missing required payment information'
        }
    
    try:
        amount = float(payment_info['amount'])
        if amount <= 0:
            return {
                'success': False,
                'error': 'Amount must be greater than zero'
            }
    except (ValueError, TypeError):
        return {
            'success': False,
            'error': 'Invalid amount format'
        }
    
    # Generate a unique payment ID
    payment_id = str(uuid.uuid4())
    
    try:
        # Create initial payment record
        payment_record = {
            'payment_id': payment_id,
            'amount': amount,
            'currency': payment_info['currency'].upper(),
            'status': 'intent_created',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'user_id': g.user.id if hasattr(g, 'user') and hasattr(g.user, 'id') else None,
            'metadata': metadata or {}
        }
        
        payment_db.insert_one(payment_record)
        
        # If we're in test mode or no provider is configured, simulate intent creation
        if not payment_provider or current_app.config.get('PAYMENT_TEST_MODE', False):
            client_secret = f"test_pi_{payment_id}_secret_123456789"
            
            return {
                'success': True,
                'payment_id': payment_id,
                'client_secret': client_secret,
                'test_mode': True
            }
        
        # Create payment intent with the actual provider
        provider_name = current_app.config.get('PAYMENT_PROVIDER')
        logger.info(f"Creating payment intent via {provider_name}")
        
        provider_result = None
        
        # Route to appropriate provider-specific processing
        if provider_name == 'stripe':
            provider_result = create_stripe_payment_intent(payment_provider, payment_info, payment_id, metadata)
        elif provider_name == 'paypal':
            provider_result = create_paypal_payment_intent(payment_provider, payment_info, payment_id, metadata)
        else:
            provider_result = {
                'success': False,
                'error': f"Unsupported payment provider: {provider_name}"
            }
        
        # Update payment record with provider result
        payment_db.update_one(
            {'payment_id': payment_id},
            {'$set': {
                'provider_intent_id': provider_result.get('provider_intent_id'),
                'client_secret': provider_result.get('client_secret'),
                'error': provider_result.get('error'),
                'updated_at': datetime.utcnow()
            }}
        )
        
        provider_result['payment_id'] = payment_id
        return provider_result
        
    except Exception as e:
        logger.error(f"Payment intent creation error: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def create_stripe_payment_intent(stripe_client, payment_info, payment_id, metadata):
    """
    Create a payment intent via Stripe.
    
    Args:
        stripe_client: Stripe client
        payment_info (dict): Payment information
        payment_id (str): Payment ID
        metadata (dict): Additional metadata
        
    Returns:
        dict: Payment intent result
    """
    # This is a placeholder for actual Stripe integration
    logger.info("Stripe payment intent creation is not fully implemented")
    
    # Simulate Stripe payment intent for now
    client_secret = f"pi_{payment_id}_secret_123456789"
    
    return {
        'success': True,
        'provider_intent_id': f"pi_{payment_id}",
        'client_secret': client_secret
    }

def create_paypal_payment_intent(paypal_client, payment_info, payment_id, metadata):
    """
    Create a payment intent via PayPal.
    
    Args:
        paypal_client: PayPal client
        payment_info (dict): Payment information
        payment_id (str): Payment ID
        metadata (dict): Additional metadata
        
    Returns:
        dict: Payment intent result
    """
    # This is a placeholder for actual PayPal integration
    logger.info("PayPal payment intent creation is not fully implemented")
    
    # Simulate PayPal payment intent for now
    client_secret = f"paypal_{payment_id}_secret_123456789"
    
    return {
        'success': True,
        'provider_intent_id': f"paypal_{payment_id}",
        'client_secret': client_secret
    }
