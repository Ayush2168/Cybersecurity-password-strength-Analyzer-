# models.py - user and admin classes

from abc import ABC, abstractmethod
from datetime import datetime
import json


class Person(ABC):


    def __init__(self, user_id: str, name: str, email: str):
        self._user_id = user_id
        self._name = name
        self._email = email

 
    @property
    def user_id(self):
        return self._user_id

    @property
    def name(self):
        return self._name

    @property
    def email(self):
        return self._email

    @abstractmethod
    def display_details(self) -> str:

        pass

    def update_profile(self, name: str = None, email: str = None):
        if name:
            self._name = name
        if email:
            self._email = email
        print(f"  Profile updated for {self._name}.")

    def __repr__(self):
        return f"{self.__class__.__name__}(id={self._user_id}, name={self._name})"

    def __str__(self):
        return f"[{self.__class__.__name__}] {self._name} <{self._email}>"


class User(Person):


    def __init__(self, user_id: str, name: str, email: str):
        super().__init__(user_id, name, email)
        self.__password_history = []     
        self.__security_score = 0

    @property
    def password_history(self):
        return self.__password_history

    @property
    def security_score(self):
        return self.__security_score

    def display_details(self) -> str:

        info = (
            f"\n{'='*40}\n"
            f"  USER PROFILE\n"
            f"{'='*40}\n"
            f"  ID     : {self._user_id}\n"
            f"  Name   : {self._name}\n"
            f"  Email  : {self._email}\n"
            f"  Analyses Done : {len(self.__password_history)}\n"
            f"  Avg Security Score : {self.__security_score}\n"
            f"{'='*40}"
        )
        print(info)
        return info

    def add_to_history(self, record: dict):
        self.__password_history.append(record)
        scores = [r.get("score", 0) for r in self.__password_history]
        self.__security_score = round(sum(scores) / len(scores), 2) if scores else 0

    def view_history(self):
        if not self.__password_history:
            print("  No password analysis history found.")
            return
        print(f"\n{'='*50}")
        print(f"  PASSWORD HISTORY FOR: {self._name}")
        print(f"{'='*50}")
        for i, record in enumerate(self.__password_history, 1):
            print(f"  [{i}] Password : {'*' * len(record.get('password',''))} | "
                  f"Score: {record.get('score', 0)}/100 | "
                  f"Level: {record.get('level','N/A')} | "
                  f"Date: {record.get('date','N/A')}")

    def search_history_recursive(self, keyword: str, index: int = 0) -> list:

        if index >= len(self.__password_history):
            return []
        record = self.__password_history[index]
        results = []
        if keyword.lower() in record.get("level", "").lower():
            results.append(record)
        return results + self.search_history_recursive(keyword, index + 1)

    def to_dict(self) -> dict:
        return {
            "user_id": self._user_id,
            "name": self._name,
            "email": self._email,
            "password_history": self.__password_history,
            "security_score": self.__security_score
        }

    @classmethod
    def from_dict(cls, data: dict):
        user = cls(data["user_id"], data["name"], data["email"])
        for record in data.get("password_history", []):
            user.add_to_history(record)
        return user

    def __len__(self):

        return len(self.__password_history)


class Admin(Person):


    def __init__(self, user_id: str, name: str, email: str, admin_id: str):
        super().__init__(user_id, name, email)
        self.__admin_id = admin_id

    @property
    def admin_id(self):
        return self.__admin_id

    def display_details(self) -> str:

        info = (
            f"\n{'='*40}\n"
            f"  ADMIN PROFILE\n"
            f"{'='*40}\n"
            f"  ID       : {self._user_id}\n"
            f"  Admin ID : {self.__admin_id}\n"
            f"  Name     : {self._name}\n"
            f"  Email    : {self._email}\n"
            f"{'='*40}"
        )
        print(info)
        return info

    def generate_reports(self, system) -> str:
        return system.generate_reports()

    def manage_users(self, system) -> list:
        return list(system.users.keys())
