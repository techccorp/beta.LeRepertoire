# ------------------------------------------------------------
# models/auth_model.py
# ------------------------------------------------------------
class User:
    """
    Represents a user in the database.
    """
    def __init__(self, payroll_id, username, email, password, created_at=None):
        self.payroll_id = payroll_id
        self.username = username
        self.email = email
        self.password = password
        self.created_at = created_at

    @staticmethod
    def from_dict(data):
        return User(
            payroll_id=data.get("payroll_id"),
            username=data.get("username"),
            email=data.get("email"),
            password=data.get("password"),
            created_at=data.get("created_at")
        )

    def to_dict(self):
        return {
            "payroll_id": self.payroll_id,
            "username": self.username,
            "email": self.email,
            "password": self.password,
            "created_at": self.created_at
        }

    def save(self):
        """
        Save the user to the database.
        """
        collection = get_db("users")
        collection.update_one(
            {"payroll_id": self.payroll_id},
            {"$set": self.to_dict()},
            upsert=True
        )

    @staticmethod
    def find_by_email(email):
        """
        Find a user by their email.
        """
        collection = get_db("users")
        data = collection.find_one({"email": email})
        return User.from_dict(data) if data else None

    @staticmethod
    def find_by_id(payroll_id):
        """
        Find a user by their ID.
        """
        collection = get_db("users")
        data = collection.find_one({"payroll_id": payroll_id})
        return User.from_dict(data) if data else None

    @staticmethod
    def find_all():
        """
        Retrieve all users.
        """
        collection = get_db("users")
        return [User.from_dict(doc) for doc in collection.find()]

class PasswordResetRequest:
    """
    Tracks password reset requests for logging or audit purposes.
    """
    def __init__(self, request_id, email, requested_at, ip_address):
        self.request_id = request_id
        self.email = email
        self.requested_at = requested_at
        self.ip_address = ip_address

    @staticmethod
    def from_dict(data):
        return PasswordResetRequest(
            request_id=data.get("request_id"),
            email=data.get("email"),
            requested_at=data.get("requested_at"),
            ip_address=data.get("ip_address")
        )

    def to_dict(self):
        return {
            "request_id": self.request_id,
            "email": self.email,
            "requested_at": self.requested_at,
            "ip_address": self.ip_address
        }

    def save(self):
        """
        Save the password reset request to the database.
        """
        collection = get_db("password_reset_requests")
        collection.update_one(
            {"request_id": self.request_id},
            {"$set": self.to_dict()},
            upsert=True
        )

    @staticmethod
    def find_by_email(email):
        """
        Find password reset requests by email.
        """
        collection = get_db("password_reset_requests")
        return [PasswordResetRequest.from_dict(doc) for doc in collection.find({"email": email})]