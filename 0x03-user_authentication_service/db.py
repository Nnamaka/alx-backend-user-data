#!/usr/bin/env python3
"""
DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db",
                                     echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        save user to the database
        Args:
            email (str): user's email
            hashed_password (str): hashed password
        Return:
            User object
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        Finds and returns a user
        Args:
            kwargs (dict): arbitrary keyword argument
        Return:
            User object
        """
        users = self._session.query(User)

        for key, val in kwargs.items():
            if key not in User.__dict__:
                raise InvalidRequestError
            
            for userr in users:
                if getattr(userr, key) == val:
                    return userr
                
        raise NoResultFound

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Updates a user
        Args:
            user_id (int): user's id
            kwargs (dict): arbitrary keyword argument
        """
        try:
            userr = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError()
        
        for key, val in kwargs.items():
            if hasattr(userr, key):
                setattr(userr, key, val)
            else:
                raise ValueError
            
        self._session.commit()