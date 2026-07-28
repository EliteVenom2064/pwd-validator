"""Shared building blocks used by the password strength checker."""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern, Tuple


@dataclass
class CheckAccumulator:
    """Collects the score and the pass/fail/feedback messages of every check."""

    score: int = 0
    feedback: List[str] = field(default_factory=list)
    passed_checks: List[str] = field(default_factory=list)
    failed_checks: List[str] = field(default_factory=list)

    def record_pass(self, label: Optional[str] = None, points: int = 0) -> None:
        if label:
            self.passed_checks.append(label)
        self.score += points

    def record_fail(
        self,
        label: Optional[str] = None,
        advice: Optional[str] = None,
        penalty: int = 0,
    ) -> None:
        if label:
            self.failed_checks.append(label)
        if advice:
            self.add_advice(advice)
        if penalty:
            self.score = max(0, self.score - penalty)

    def add_advice(self, advice: str) -> None:
        self.feedback.append(advice)

    def capped_score(self, maximum: int = 100) -> int:
        return min(maximum, self.score)


@dataclass(frozen=True)
class CharacterRule:
    """A "password must contain X" rule expressed as a regular expression."""

    pattern: Pattern[str]
    points: int
    passed_label: str
    failed_label: str
    advice: str

    def apply(self, password: str, accumulator: CheckAccumulator) -> None:
        if self.pattern.search(password):
            accumulator.record_pass(self.passed_label, self.points)
        else:
            accumulator.record_fail(self.failed_label, self.advice)


CHARACTER_RULES: Tuple[CharacterRule, ...] = (
    CharacterRule(
        pattern=re.compile(r'[a-z]'),
        points=10,
        passed_label='Contains lowercase letters',
        failed_label='Missing lowercase letters',
        advice='Add lowercase letters (a-z)',
    ),
    CharacterRule(
        pattern=re.compile(r'[A-Z]'),
        points=10,
        passed_label='Contains uppercase letters',
        failed_label='Missing uppercase letters',
        advice='Add uppercase letters (A-Z)',
    ),
    CharacterRule(
        pattern=re.compile(r'\d'),
        points=10,
        passed_label='Contains numbers',
        failed_label='Missing numbers',
        advice='Add numbers (0-9)',
    ),
    CharacterRule(
        pattern=re.compile(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]'),
        points=15,
        passed_label='Contains special characters',
        failed_label='Missing special characters',
        advice='Add special characters (!@#$%^&*)',
    ),
)

# (minimum length, bonus points, label) awarded on top of the minimum length check.
LENGTH_BONUSES: Tuple[Tuple[int, int, str], ...] = (
    (12, 10, 'Good length'),
    (16, 10, 'Excellent length'),
)


def has_any_substring(password: str, patterns) -> bool:
    pwd_lower = password.lower()
    return any(pattern in pwd_lower for pattern in patterns)


def has_sequential_chars(password: str, run_length: int = 3) -> bool:
    for start in range(len(password) - run_length + 1):
        codes = [ord(char) for char in password[start:start + run_length]]
        if all(later == earlier + 1 for earlier, later in zip(codes, codes[1:])):
            return True
    return False
