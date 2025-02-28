# ------------------------------------------------#
#           utils/defense/rate_limiter.py         #
#-------------------------------------------------#
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Rate limiter implementation for controlling access attempts
    Uses in-memory storage with thread-safe operations
    """
    
    def __init__(self, max_attempts: int, window_seconds: int, block_seconds: int):
        """
        Initialize rate limiter
        
        Args:
            max_attempts: Maximum number of attempts allowed
            window_seconds: Time window in seconds to track attempts
            block_seconds: Duration in seconds to block after max attempts reached
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self.attempts = defaultdict(list)
        self.blocks = defaultdict(datetime)
        self._lock = threading.Lock()
        
    def is_blocked(self, key: str) -> bool:
        """
        Check if a key is currently blocked
        
        Args:
            key: Identifier to check (e.g., payroll_id, IP address)
            
        Returns:
            bool: True if blocked, False otherwise
        """
        with self._lock:
            self._cleanup(key)
            block_time = self.blocks.get(key)
            if block_time and datetime.utcnow() < block_time:
                return True
            return False

    def record_attempt(self, key: str, success: bool = False) -> None:
        """
        Record an attempt for a key
        
        Args:
            key: Identifier to record attempt for
            success: Whether the attempt was successful
        """
        if success:
            self.clear_attempts(key)
            return

        with self._lock:
            self._cleanup(key)
            self.attempts[key].append(datetime.utcnow())
            
            if len(self.attempts[key]) >= self.max_attempts:
                self.blocks[key] = datetime.utcnow() + timedelta(seconds=self.block_seconds)
                logger.warning(f"Rate limit exceeded for {key}. Blocked for {self.block_seconds} seconds")

    def clear_attempts(self, key: str) -> None:
        """
        Clear all attempts and blocks for a key
        
        Args:
            key: Identifier to clear
        """
        with self._lock:
            self.attempts.pop(key, None)
            self.blocks.pop(key, None)

    def _cleanup(self, key: str) -> None:
        """
        Remove expired attempts for a key
        
        Args:
            key: Identifier to clean up
        """
        cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
        self.attempts[key] = [
            attempt for attempt in self.attempts.get(key, [])
            if attempt > cutoff
        ]
        
        # Clear block if expired
        if self.blocks.get(key) and self.blocks[key] < datetime.utcnow():
            self.blocks.pop(key)
