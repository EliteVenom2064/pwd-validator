import re
from typing import List
from dataclasses import dataclass
from enum import Enum

MAX_SCORE = 100
WEAK_CEILING = 39

class StrengthLevel(Enum):
    WEAK = 'weak'
    FAIR = 'fair'
    GOOD = 'good'
    STRONG = 'strong'
    VERY_STRONG = 'very-strong'

@dataclass
class StrengthResult:
    score: int  # 0-100
    strength: StrengthLevel
    feedback: List[str]
    passed_checks: List[str]
    failed_checks: List[str]
    verdict: str = ''

class PasswordStrengthChecker:
    COMMON_PATTERNS = frozenset({
        'password', 'qwerty', 'letmein', 'admin', 'monkey', 'dragon',
        'welcome', 'iloveyou', 'sunshine', 'football',
    })
    SPECIAL_CHARS = re.compile(r'[^A-Za-z0-9]')
    MAX_REPEAT_RUN = 3

    def __init__(self, min_length: int = 8, max_length: int = 128):
        if min_length < 1:
            raise ValueError('min_length must be at least 1')
        if max_length < min_length:
            raise ValueError('max_length must be greater than or equal to min_length')
        self.min_length = min_length
        self.max_length = max_length
        self.common_patterns = set(self.COMMON_PATTERNS)

    def check_strength(self, password: str) -> StrengthResult:
        if not isinstance(password, str):
            raise TypeError(f'password must be a str, got {type(password).__name__}')

        feedback: List[str] = []
        passed_checks: List[str] = []
        failed_checks: List[str] = []
        score = 0
        length_ok = True

        # Check 1: Length
        if len(password) < self.min_length:
            length_ok = False
            failed_checks.append('Too short')
            feedback.append(f'Password must be at least {self.min_length} characters long')
        elif len(password) > self.max_length:
            length_ok = False
            failed_checks.append('Too long')
            feedback.append(f'Password must be at most {self.max_length} characters long')
        else:
            passed_checks.append('Meets minimum length')
            score += 15
            if len(password) >= 12:
                score += 10
                passed_checks.append('Good length')
            if len(password) >= 16:
                score += 10
                passed_checks.append('Excellent length')

        # Check 2: Lowercase letters
        if re.search(r'[a-z]', password):
            passed_checks.append('Contains lowercase letters')
            score += 15
        else:
            failed_checks.append('Missing lowercase letters')
            feedback.append('Add lowercase letters (a-z)')

        # Check 3: Uppercase letters
        if re.search(r'[A-Z]', password):
            passed_checks.append('Contains uppercase letters')
            score += 15
        else:
            failed_checks.append('Missing uppercase letters')
            feedback.append('Add uppercase letters (A-Z)')

        # Check 4: Numbers
        if re.search(r'[0-9]', password):
            passed_checks.append('Contains numbers')
            score += 15
        else:
            failed_checks.append('Missing numbers')
            feedback.append('Add numbers (0-9)')

        # Check 5: Special characters
        if self.SPECIAL_CHARS.search(password):
            passed_checks.append('Contains special characters')
            score += 20
        else:
            failed_checks.append('Missing special characters')
            feedback.append('Add special characters (!@#$%^&*)')

        # Check 6: Common patterns
        if self._has_common_patterns(password):
            failed_checks.append('Contains common patterns')
            score -= 20
            feedback.append('Avoid common words like "password", "qwerty", or "admin"')
        else:
            passed_checks.append('No common weak patterns')

        # Check 7: Sequential characters
        if self._has_sequential_chars(password):
            failed_checks.append('Contains sequential characters')
            score -= 10
            feedback.append('Avoid sequential characters (abc, 123, zyx)')
        else:
            passed_checks.append('No sequential characters')

        # Check 8: Repeated characters
        if self._has_repeated_chars(password):
            failed_checks.append('Contains repeated characters')
            score -= 10
            feedback.append(
                f'Avoid repeating the same character {self.MAX_REPEAT_RUN} or more times in a row'
            )
        else:
            passed_checks.append('No repeated characters')

        if not length_ok:
            # A password outside the configured length policy can never rate above weak.
            score = min(score, WEAK_CEILING)
        score = max(0, min(MAX_SCORE, score))
        strength = self._get_strength_level(score)

        verdict = ''
        if strength == StrengthLevel.VERY_STRONG:
            verdict = 'Excellent password!'
        elif strength == StrengthLevel.STRONG:
            verdict = 'Good password, but could be stronger'

        return StrengthResult(
            score=score,
            strength=strength,
            feedback=feedback,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            verdict=verdict,
        )

    def _has_common_patterns(self, password: str) -> bool:
        pwd_lower = password.lower()
        return any(pattern in pwd_lower for pattern in self.common_patterns)

    def _has_sequential_chars(self, password: str) -> bool:
        """Detect ascending or descending runs of 3+ chars within one character class."""
        for i in range(len(password) - 2):
            window = password[i:i + 3]
            if not self._same_class(window):
                continue
            deltas = {ord(window[j + 1]) - ord(window[j]) for j in range(2)}
            if deltas == {1} or deltas == {-1}:
                return True
        return False

    def _has_repeated_chars(self, password: str) -> bool:
        run = 1
        for prev, char in zip(password, password[1:]):
            run = run + 1 if char == prev else 1
            if run >= self.MAX_REPEAT_RUN:
                return True
        return False

    @staticmethod
    def _same_class(chars: str) -> bool:
        return (all(c.islower() and c.isascii() for c in chars)
                or all(c.isupper() and c.isascii() for c in chars)
                or all(c.isdigit() and c.isascii() for c in chars))

    def _get_strength_level(self, score: int) -> StrengthLevel:
        if score >= 90:
            return StrengthLevel.VERY_STRONG
        elif score >= 75:
            return StrengthLevel.STRONG
        elif score >= 60:
            return StrengthLevel.GOOD
        elif score >= 40:
            return StrengthLevel.FAIR
        else:
            return StrengthLevel.WEAK

# Example usage
if __name__ == '__main__':
    checker = PasswordStrengthChecker()

    test_passwords = [
        'password',
        'Password1',
        'P@ssw0rd',
        'C0mpl3x!P@ss#2024',
        'MyStr0ng!Pass@2024#Secure',
    ]

    for pwd in test_passwords:
        result = checker.check_strength(pwd)
        print(f'\nPassword: {pwd}')
        print(f'Strength: {result.strength.value} ({result.score}/100)')
        print(f'Passed: {result.passed_checks}')
        print(f'Failed: {result.failed_checks}')
        if result.feedback:
            print(f'Feedback: {result.feedback}')
        if result.verdict:
            print(f'Verdict: {result.verdict}')
