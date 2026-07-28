import re
from typing import List
from dataclasses import dataclass
from enum import Enum

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

class PasswordStrengthChecker:
    def __init__(self, min_length: int = 8, max_length: int = 128):
        if min_length < 1:
            raise ValueError('min_length must be at least 1')
        if max_length < min_length:
            raise ValueError('max_length must be greater than or equal to min_length')
        self.min_length = min_length
        self.max_length = max_length
        self.common_patterns = [
            'password', '123456', 'qwerty', 'abc', 'letmein',
            'admin', 'monkey', 'dragon'
        ]

    def check_strength(self, password: str) -> StrengthResult:
        if not isinstance(password, str):
            raise TypeError(f'password must be a str, got {type(password).__name__}')

        feedback = []
        passed_checks = []
        failed_checks = []
        score = 0

        # Check 1: Length
        if len(password) > self.max_length:
            failed_checks.append('Too long')
            feedback.append(f'Password must be at most {self.max_length} characters long')
        elif len(password) < self.min_length:
            failed_checks.append('Too short')
            feedback.append(f'Password must be at least {self.min_length} characters long')
        else:
            passed_checks.append('Meets minimum length')
            score += 10
            if len(password) >= 12:
                score += 10
                passed_checks.append('Good length')
            if len(password) >= 16:
                score += 10
                passed_checks.append('Excellent length')

        # Check 2: Lowercase letters
        if re.search(r'[a-z]', password):
            passed_checks.append('Contains lowercase letters')
            score += 10
        else:
            failed_checks.append('Missing lowercase letters')
            feedback.append('Add lowercase letters (a-z)')

        # Check 3: Uppercase letters
        if re.search(r'[A-Z]', password):
            passed_checks.append('Contains uppercase letters')
            score += 10
        else:
            failed_checks.append('Missing uppercase letters')
            feedback.append('Add uppercase letters (A-Z)')

        # Check 4: Numbers
        if re.search(r'\d', password):
            passed_checks.append('Contains numbers')
            score += 10
        else:
            failed_checks.append('Missing numbers')
            feedback.append('Add numbers (0-9)')

        # Check 5: Special characters
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
            passed_checks.append('Contains special characters')
            score += 15
        else:
            failed_checks.append('Missing special characters')
            feedback.append('Add special characters (!@#$%^&*)')

        # Check 6: Common patterns
        if self._has_common_patterns(password):
            failed_checks.append('Contains common patterns')
            score = max(0, score - 20)
            feedback.append('Avoid common patterns like "123", "abc", or repetitive characters')
        else:
            passed_checks.append('No common weak patterns')

        # Check 7: Sequential characters
        if self._has_sequential_chars(password):
            score = max(0, score - 10)
            feedback.append('Avoid sequential characters (abc, 123)')

        strength = self._get_strength_level(min(100, score))

        if strength == StrengthLevel.VERY_STRONG:
            feedback.append('✓ Excellent password!')
        elif strength == StrengthLevel.STRONG:
            feedback.append('Good password, but could be stronger')

        return StrengthResult(
            score=min(100, score),
            strength=strength,
            feedback=feedback,
            passed_checks=passed_checks,
            failed_checks=failed_checks
        )

    def _has_common_patterns(self, password: str) -> bool:
        pwd_lower = password.lower()
        return any(pattern in pwd_lower for pattern in self.common_patterns)

    def _has_sequential_chars(self, password: str) -> bool:
        for i in range(len(password) - 2):
            for step in (1, -1):
                if (ord(password[i+1]) == ord(password[i]) + step and
                    ord(password[i+2]) == ord(password[i+1]) + step):
                    return True
        return False

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
