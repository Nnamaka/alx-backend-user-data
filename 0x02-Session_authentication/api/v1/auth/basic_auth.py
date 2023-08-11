#!/usr/bin/env python3
"""
Definition of class BasicAuth
"""
import base64
from .auth import Auth
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """ Basic Auth class
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Extracts the Base64 from Authorization header
        """
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.split(" ")[-1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """
        Decode Base64
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_string = base64.b64decode(
                base64_authorization_header.encode('utf-8'))
            return decoded_string.decode('utf-8')

        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> (str, str):
        """
        get user email and password from base64 decoded string
        """
        if decoded_base64_authorization_header is None:
            return (None, None)

        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)

        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        user_email = decoded_base64_authorization_header.split(":")[0]
        user_password = decoded_base64_authorization_header[len(
            user_email) + 1:]

        return (user_email, user_password)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Get User instance based on email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({"email": user_email})
            if not users or users is None:
                return None

            for user in users:
                if user.is_valid_password(user_pwd):
                    return user

            return None

        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        get User instance from request
        """
        Auth_header = self.authorization_header(request)
        if Auth_header is not None:
            base64_extract = self.extract_base64_authorization_header(
                Auth_header)

        if base64_extract is not None:
            decoded = self.decode_base64_authorization_header(base64_extract)

        if decoded is not None:
            creds = self.extract_user_credentials(decoded)

        if creds is not None:
            return self.user_object_from_credentials(creds[0], creds[1])
        return
