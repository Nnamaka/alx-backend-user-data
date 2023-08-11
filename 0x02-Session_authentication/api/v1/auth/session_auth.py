#!/usr/bin/env python3
"""
Session Auth module
"""

from api.v1.auth.auth import Auth
from models.user import User
import uuid

class SessionAuth(Auth):
    """ SessionAuth with Auth as base class """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Creates Session ID for user
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        
        session_id = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id