from typing import List
from dataclasses import dataclass
from enum import Enum

from password_checks import (
    CHARACTER_RULES,
    LENGTH_BONUSES,
    CheckAccumulator,
    has_any_substring,
    has_sequential_chars,
)

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

# (minimum score, level), highest first.
STRENGTH_THRESHOLDS = (
    (90, StrengthLevel.VERY_STRONG),
    (75, StrengthLevel.STRONG),
    (60, StrengthLevel.GOOD),
    (40, StrengthLevel.FAIR),
)

SUMMARY_FEEDBACK = {
    StrengthLevel.VERY_STRONG: '✓ Excellent password!',
    StrengthLevel.STRONG: 'Good password, but could be stronger',
}

class PasswordStrengthChecker:
    def __init__(self, min_length: int = 8, max_length: int = 128):
        self.min_length = min_length
        self.max_length = max_length
        self.common_patterns = [
            'password', '123456', 'qwerty', 'abc', 'letmein',
            'admin', 'monkey', 'dragon'
        ]

    def check_strength(self, password: str) -> StrengthResult:
        checks = CheckAccumulator()

        self._check_length(password, checks)

        for rule in CHARACTER_RULES:
            rule.apply(password, checks)

        if self._has_common_patterns(password):
            checks.record_fail(
                'Contains common patterns',
                'Avoid common patterns like "123", "abc", or repetitive characters',
                penalty=20,
            )
        else:
            checks.record_pass('No common weak patterns')

        if self._has_sequential_chars(password):
            checks.record_fail(advice='Avoid sequential characters (abc, 123)', penalty=10)

        score = checks.capped_score()
        strength = self._get_strength_level(score)

        summary = SUMMARY_FEEDBACK.get(strength)
        if summary:
            checks.add_advice(summary)

        return StrengthResult(
            score=score,
            strength=strength,
            feedback=checks.feedback,
            passed_checks=checks.passed_checks,
            failed_checks=checks.failed_checks
        )

    def _check_length(self, password: str, checks: CheckAccumulator) -> None:
        if len(password) < self.min_length:
            checks.record_fail(
                'Too short',
                f'Password must be at least {self.min_length} characters long',
            )
            return

        checks.record_pass('Meets minimum length', 10)
        for minimum, points, label in LENGTH_BONUSES:
            if len(password) >= minimum:
                checks.record_pass(label, points)

    def _has_common_patterns(self, password: str) -> bool:
        return has_any_substring(password, self.common_patterns)

    def _has_sequential_chars(self, password: str) -> bool:
        return has_sequential_chars(password)

    def _get_strength_level(self, score: int) -> StrengthLevel:
        for minimum, level in STRENGTH_THRESHOLDS:
            if score >= minimum:
                return level
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
