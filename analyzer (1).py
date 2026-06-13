# analyzer.py - password analysis, scoring, and generation

import re
import math
import random
import string
from datetime import datetime
from crack_time import CrackTimeEstimator




class EmptyPasswordError(Exception):
    pass

class WeakPasswordError(Exception):
    pass

class InvalidPasswordFormatError(Exception):
    pass




def log_analysis(func):

    def wrapper(*args, **kwargs):
        print(f"\n  [LOG] Running {func.__name__}() at {datetime.now().strftime('%H:%M:%S')}")
        result = func(*args, **kwargs)
        print(f"  [LOG] {func.__name__}() completed.")
        return result
    return wrapper

def log_generation(func):

    def wrapper(*args, **kwargs):
        print(f"\n  [LOG] Generating password via {func.__name__}()...")
        result = func(*args, **kwargs)
        print(f"  [LOG] Generation complete.")
        return result
    return wrapper




class Password:


    PASSWORD_RULES = (
        "Minimum 8 characters",
        "At least one uppercase letter",
        "At least one lowercase letter",
        "At least one digit",
        "At least one special character",
        "Not a common/dictionary password",
    )


    MODE_ENTROPY   = "entropy"
    MODE_CRACK     = "crack"
    MODE_MIXED     = "mixed"

    def __init__(self, password_text: str):
        if not isinstance(password_text, str):
            raise InvalidPasswordFormatError("Password must be a string!")
        if not password_text or not password_text.strip():
            raise EmptyPasswordError("Password cannot be empty!")

        self.__password_text = password_text
        self.length   = len(password_text)
        self.strength = "Unknown"

    @property
    def password_text(self):
        return self.__password_text

    def calculate_strength(self, score: int) -> str:
        if score <= 20:
            self.strength = "Very Weak"
        elif score <= 40:
            self.strength = "Weak"
        elif score <= 60:
            self.strength = "Moderate"
        elif score <= 80:
            self.strength = "Strong"
        else:
            self.strength = "Very Strong"
        return self.strength

    @staticmethod
    def get_charset_size(password: str) -> int:

        pool = 0
        if re.search(r'[a-z]', password): pool += 26
        if re.search(r'[A-Z]', password): pool += 26
        if re.search(r'\d',    password): pool += 10
        if re.search(r'[^a-zA-Z0-9]', password): pool += 32
        return pool if pool > 0 else 1

    def analyze_password(self) -> dict:

        p = self.__password_text
        return {
            "length":    self.length,
            "uppercase": bool(re.search(r'[A-Z]', p)),
            "lowercase": bool(re.search(r'[a-z]', p)),
            "digits":    bool(re.search(r'\d',    p)),
            "special":   bool(re.search(r'[^a-zA-Z0-9]', p)),
        }

    def __str__(self):
        return f"Password(masked={'*'*self.length}, length={self.length}, strength={self.strength})"

    def __repr__(self):
        return f"Password(length={self.length})"

    def __len__(self):
        return self.length




class PasswordAnalyzer:


    def __init__(self):
        self.analysis_id    = f"ANA-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.password_score = 0

    @log_analysis
    def check_complexity(self, password: Password) -> dict:
        p = password.password_text
        return {
            "length_ok":   password.length >= 8,
            "has_upper":   bool(re.search(r'[A-Z]', p)),
            "has_lower":   bool(re.search(r'[a-z]', p)),
            "has_digit":   bool(re.search(r'\d',    p)),
            "has_special": bool(re.search(r'[^a-zA-Z0-9]', p)),
        }

    def calculate_entropy(self, password: Password) -> float:

        charset = Password.get_charset_size(password.password_text)
        return round(password.length * math.log2(charset), 2)

    def detect_patterns(self, password_text: str) -> set:

        patterns = set()
        if re.search(r'(.)\1{2,}', password_text):
            patterns.add("Repeated characters (e.g. aaa, 111)")
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password_text):
            patterns.add("Sequential numbers (e.g. 123)")
        if re.search(
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            password_text.lower()
        ):
            patterns.add("Sequential letters (e.g. abc)")
        if re.search(r'(qwerty|asdf|zxcv|qazwsx|1qaz|2wsx)', password_text.lower()):
            patterns.add("Keyboard pattern (e.g. qwerty)")
        return patterns

    def score_password(self, password: Password, issues: list) -> int:

        score = 0
        p = password.password_text

        if password.length >= 8:  score += 10
        if password.length >= 12: score += 10
        if password.length >= 16: score += 10

        if re.search(r'[A-Z]', p): score += 15
        if re.search(r'[a-z]', p): score += 15
        if re.search(r'\d',    p): score += 15
        if re.search(r'[^a-zA-Z0-9]', p): score += 20

        types = sum([
            bool(re.search(r'[A-Z]', p)),
            bool(re.search(r'[a-z]', p)),
            bool(re.search(r'\d',    p)),
            bool(re.search(r'[^a-zA-Z0-9]', p)),
        ])
        if types == 4: score += 5

        score -= len(issues) * 8
        self.password_score = max(0, min(100, score))
        return self.password_score

    def score_from_entropy(self, entropy: float) -> int:

        if entropy >= 100: return 100
        if entropy >= 80:  return 85 + round((entropy - 80) / 20 * 15)
        if entropy >= 60:  return 70 + round((entropy - 60) / 20 * 15)
        if entropy >= 40:  return 50 + round((entropy - 40) / 20 * 20)
        if entropy >= 25:  return 30 + round((entropy - 25) / 15 * 20)
        if entropy >= 10:  return 10 + round((entropy - 10) / 15 * 20)
        return max(0, round(entropy))

    def score_mixed(self, password: Password, issues: list, entropy: float) -> int:

        e_score = self.score_from_entropy(entropy)
        c_score = self.score_password(password, issues)
        return max(0, min(100, round(0.55 * e_score + 0.45 * c_score)))

    def compute_final_score(
        self,
        password: Password,
        issues: list,
        entropy: float,
        mode: str = Password.MODE_MIXED,
    ) -> int:

        if mode == Password.MODE_ENTROPY:
            score = self.score_from_entropy(entropy)
        elif mode == Password.MODE_CRACK:
            estimator = CrackTimeEstimator(entropy)
            estimator.estimate_all()
            score = estimator.score_from_crack_time()
        else:
            score = self.score_mixed(password, issues, entropy)

        self.password_score = score
        return score

    @classmethod
    def get_security_statistics(cls, users: dict) -> dict:

        all_scores = []
        for user in users.values():
            for record in user.password_history:
                all_scores.append(record.get("score", 0))
        avg = round(sum(all_scores) / len(all_scores), 2) if all_scores else 0
        return {
            "total_users":     len(users),
            "total_analyses":  sum(len(u) for u in users.values()),
            "average_score":   avg,
        }




class VulnerabilityScanner:


    def __init__(self, common_passwords_path: str = "data/common_passwords.txt"):
        self.detected_risks       = []
        self.__weak_password_list = self.__load_weak_passwords(common_passwords_path)

    def __load_weak_passwords(self, path: str) -> set:
        try:
            with open(path, 'r') as f:
                return {line.strip().lower() for line in f if line.strip()}
        except FileNotFoundError:
            print(f"  [WARNING] Common passwords file not found at '{path}'.")
            return set()

    def scan_password(self, password: Password, patterns: set) -> list:

        issues = []
        p = password.password_text

        if password.length < 8:
            issues.append("Too short (minimum 8 characters required)")
        if not re.search(r'[A-Z]', p):
            issues.append("Missing uppercase letter")
        if not re.search(r'[a-z]', p):
            issues.append("Missing lowercase letter")
        if not re.search(r'\d', p):
            issues.append("Missing digit")
        if not re.search(r'[^a-zA-Z0-9]', p):
            issues.append("Missing special character")
        if p.lower() in self.__weak_password_list:
            issues.append("Found in common passwords dictionary")

        for pattern in patterns:
            issues.append(f"Weak pattern detected: {pattern}")

        self.detected_risks = issues
        return issues

    def detect_common_patterns(self, password_text: str) -> list:
        risky = []
        if re.fullmatch(r'\d+', password_text):
            risky.append("All digits")
        if re.fullmatch(r'[a-zA-Z]+', password_text):
            risky.append("All letters only")
        if len(set(password_text)) <= 3:
            risky.append("Very low character variety")
        return risky




class PasswordGenerator:


    def __init__(self):
        self.generated_password = ""

    @log_generation
    def generate_password(self, length: int = 16) -> str:

        length = max(8, length)
        chars = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
            random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"),
        ]
        all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
        chars += [random.choice(all_chars) for _ in range(length - 4)]
        random.shuffle(chars)
        self.generated_password = ''.join(chars)
        return self.generated_password

    def suggest_password(self, base: str = "") -> str:
        suggestions = []
        if base:
            enhanced = (
                base.replace('a','@').replace('e','3')
                    .replace('i','!').replace('o','0').replace('s','$')
            )
            if len(enhanced) < 12:
                enhanced += random.choice(string.digits) + random.choice("!@#$%")
            suggestions.append(enhanced)
        suggestions.append(self.generate_password(14))
        print("\n  Suggested strong passwords:")
        for i, s in enumerate(suggestions, 1):
            print(f"    [{i}] {s}")
        return suggestions[0]

    sort_by_score = staticmethod(lambda records: sorted(records, key=lambda r: r.get("score", 0), reverse=True))
    sort_by_risk  = staticmethod(lambda records: sorted(records, key=lambda r: r.get("score", 0)))
