#!/usr/bin/env python3
"""Auth class"""

from flask import request
from typing import List, TypeVar


class Auth:
    """API authentication."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Required paths
        Args:
            - path(str): Url path
            - excluded_paths(List of str): List of allowed paths
        Return:
            - True if path is not in excluded_paths, else False
        """

        if path is None:
            return True

        # make 'path' forward slash tolerant
        if path[-1] != '/':
            path += '/'

        if excluded_paths is None or not excluded_paths:
            return True
        elif path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """Request validation"""
        if request is None or "Authorization" not in request.headers:
            return None
        
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """current user"""
        return None
