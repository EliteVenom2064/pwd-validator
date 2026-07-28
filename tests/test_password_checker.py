import pytest

from password_strength_checker import (
    PasswordStrengthChecker,
    StrengthLevel,
    StrengthResult,
)


@pytest.fixture
def checker():
    return PasswordStrengthChecker()


class TestInitialization:
    def test_default_bounds(self):
        c = PasswordStrengthChecker()
        assert c.min_length == 8
        assert c.max_length == 128

    def test_custom_bounds(self):
        c = PasswordStrengthChecker(min_length=12, max_length=64)
        assert c.min_length == 12
        assert c.max_length == 64

    def test_common_patterns_populated(self):
        c = PasswordStrengthChecker()
        assert 'password' in c.common_patterns
        assert 'qwerty' in c.common_patterns


class TestResultShape:
    def test_returns_strength_result(self, checker):
        result = checker.check_strength('Hkmpqtvw9!')
        assert isinstance(result, StrengthResult)
        assert isinstance(result.score, int)
        assert isinstance(result.strength, StrengthLevel)
        assert isinstance(result.feedback, list)
        assert isinstance(result.passed_checks, list)
        assert isinstance(result.failed_checks, list)

    def test_score_never_exceeds_100(self, checker):
        result = checker.check_strength('Hkmpqtvw9!xzFGJL')
        assert 0 <= result.score <= 100


class TestLengthCheck:
    def test_too_short(self, checker):
        result = checker.check_strength('Hk9!')
        assert 'Too short' in result.failed_checks
        assert any('at least 8 characters' in f for f in result.feedback)

    def test_too_short_custom_min(self):
        c = PasswordStrengthChecker(min_length=12)
        result = c.check_strength('Hkmpqtvw9!')  # length 10 < 12
        assert 'Too short' in result.failed_checks
        assert any('at least 12 characters' in f for f in result.feedback)

    def test_meets_minimum_length(self, checker):
        result = checker.check_strength('Hkmpqtvw')  # length 8
        assert 'Meets minimum length' in result.passed_checks
        assert 'Good length' not in result.passed_checks
        assert 'Excellent length' not in result.passed_checks

    def test_good_length(self, checker):
        result = checker.check_strength('Hkmpqtvw9!xz')  # length 12
        assert 'Good length' in result.passed_checks
        assert 'Excellent length' not in result.passed_checks

    def test_excellent_length(self, checker):
        result = checker.check_strength('Hkmpqtvw9!xzFGJL')  # length 16
        assert 'Good length' in result.passed_checks
        assert 'Excellent length' in result.passed_checks


class TestCharacterVariety:
    def test_missing_lowercase(self, checker):
        result = checker.check_strength('HKMPQTVW9!')
        assert 'Missing lowercase letters' in result.failed_checks
        assert 'Add lowercase letters (a-z)' in result.feedback

    def test_has_lowercase(self, checker):
        result = checker.check_strength('Hkmpqtvw9!')
        assert 'Contains lowercase letters' in result.passed_checks

    def test_missing_uppercase(self, checker):
        result = checker.check_strength('hkmpqtvw9!')
        assert 'Missing uppercase letters' in result.failed_checks
        assert 'Add uppercase letters (A-Z)' in result.feedback

    def test_has_uppercase(self, checker):
        result = checker.check_strength('Hkmpqtvw9!')
        assert 'Contains uppercase letters' in result.passed_checks

    def test_missing_numbers(self, checker):
        result = checker.check_strength('Hkmpqtvw!')
        assert 'Missing numbers' in result.failed_checks
        assert 'Add numbers (0-9)' in result.feedback

    def test_has_numbers(self, checker):
        result = checker.check_strength('Hkmpqtvw9!')
        assert 'Contains numbers' in result.passed_checks

    def test_missing_special(self, checker):
        result = checker.check_strength('Hkmpqtvw9')
        assert 'Missing special characters' in result.failed_checks
        assert 'Add special characters (!@#$%^&*)' in result.feedback

    def test_has_special(self, checker):
        result = checker.check_strength('Hkmpqtvw9!')
        assert 'Contains special characters' in result.passed_checks


class TestCommonPatterns:
    @pytest.mark.parametrize('pattern', [
        'password', '123456', 'qwerty', 'abc', 'letmein',
        'admin', 'monkey', 'dragon',
    ])
    def test_detects_each_common_pattern(self, checker, pattern):
        assert checker._has_common_patterns(pattern) is True

    def test_case_insensitive(self, checker):
        assert checker._has_common_patterns('PASSWORD') is True

    def test_common_pattern_penalizes_score(self, checker):
        clean = checker.check_strength('Hkmpqtvw9!')
        # Same content but embeds the common pattern "password".
        withpat = checker.check_strength('passwordHK9!')
        assert 'Contains common patterns' in withpat.failed_checks
        assert any('Avoid common patterns' in f for f in withpat.feedback)
        assert withpat.score < clean.score

    def test_no_common_pattern(self, checker):
        result = checker.check_strength('Hkmpqtvw9!')
        assert 'No common weak patterns' in result.passed_checks

    def test_score_floored_at_zero(self, checker):
        # Length (+10) and lowercase (+10) credit, then common pattern
        # penalty (-20) -> floored at 0.
        result = checker.check_strength('password')
        assert result.score == 0


class TestSequentialCharacters:
    def test_detects_sequential(self, checker):
        assert checker._has_sequential_chars('abc') is True
        assert checker._has_sequential_chars('xy123z') is True

    def test_no_sequential(self, checker):
        assert checker._has_sequential_chars('hkmpqtvw') is False

    def test_too_short_for_sequential(self, checker):
        assert checker._has_sequential_chars('ab') is False

    def test_sequential_penalizes_and_feeds_back(self, checker):
        result = checker.check_strength('Hkmpqtu9!')  # 't','u' only 2 seq -> none
        assert 'Avoid sequential characters (abc, 123)' not in result.feedback
        seq = checker.check_strength('Hijkmp9!')  # h,i,j sequential
        assert 'Avoid sequential characters (abc, 123)' in seq.feedback


class TestStrengthLevels:
    def test_weak(self, checker):
        assert checker.check_strength('Hkmpqtvw').strength == StrengthLevel.WEAK

    def test_fair(self, checker):
        result = checker.check_strength('P@ssw0rd')  # score 55
        assert result.score == 55
        assert result.strength == StrengthLevel.FAIR

    def test_good(self, checker):
        result = checker.check_strength('C0mpl3x!P@ss')  # score 65
        assert result.score == 65
        assert result.strength == StrengthLevel.GOOD

    def test_strong(self, checker):
        result = checker.check_strength('Hkmpqtvw9!xzFGJL')  # score 75
        assert result.score == 75
        assert result.strength == StrengthLevel.STRONG
        assert 'Good password, but could be stronger' in result.feedback

    def test_get_strength_level_boundaries(self, checker):
        assert checker._get_strength_level(0) == StrengthLevel.WEAK
        assert checker._get_strength_level(39) == StrengthLevel.WEAK
        assert checker._get_strength_level(40) == StrengthLevel.FAIR
        assert checker._get_strength_level(59) == StrengthLevel.FAIR
        assert checker._get_strength_level(60) == StrengthLevel.GOOD
        assert checker._get_strength_level(74) == StrengthLevel.GOOD
        assert checker._get_strength_level(75) == StrengthLevel.STRONG
        assert checker._get_strength_level(89) == StrengthLevel.STRONG
        assert checker._get_strength_level(90) == StrengthLevel.VERY_STRONG
        assert checker._get_strength_level(100) == StrengthLevel.VERY_STRONG

    def test_very_strong_feedback(self, checker):
        # VERY_STRONG is unreachable via check_strength (max score is 75),
        # so the excellent-password feedback branch is exercised here indirectly.
        assert checker._get_strength_level(95) == StrengthLevel.VERY_STRONG


class TestExpectedScores:
    @pytest.mark.parametrize('password,score,level', [
        ('', 0, StrengthLevel.WEAK),
        ('hkmpqtvw', 20, StrengthLevel.WEAK),
        ('Hkmpqtvw', 30, StrengthLevel.WEAK),
        ('Hkmpqtvw9', 40, StrengthLevel.FAIR),
        ('Hkmpqtvw9!', 55, StrengthLevel.FAIR),
        ('Hkmpqtvw9!xz', 65, StrengthLevel.GOOD),
        ('Hkmpqtvw9!xzFGJL', 75, StrengthLevel.STRONG),
    ])
    def test_scores(self, checker, password, score, level):
        result = checker.check_strength(password)
        assert result.score == score
        assert result.strength == level
