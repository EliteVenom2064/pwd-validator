import pytest

from password_strength_checker import (
    MAX_SCORE,
    PasswordStrengthChecker,
    StrengthLevel,
)


@pytest.fixture
def checker():
    return PasswordStrengthChecker()


class TestPasswordLength:
    def test_too_short(self, checker):
        result = checker.check_strength('Ab1!')
        assert 'Too short' in result.failed_checks
        assert result.strength is StrengthLevel.WEAK

    def test_too_long(self, checker):
        result = checker.check_strength('Ab1!' + 'x' * 200)
        assert 'Too long' in result.failed_checks
        assert 'Meets minimum length' not in result.passed_checks

    def test_length_tiers(self, checker):
        assert 'Good length' in checker.check_strength('Qw7!vKm2#Xw9').passed_checks
        assert 'Excellent length' in checker.check_strength('Qw7!vKm2#Xw9$Lp4').passed_checks

    def test_custom_bounds(self):
        checker = PasswordStrengthChecker(min_length=4, max_length=6)
        assert 'Too short' not in checker.check_strength('Ab1!').failed_checks
        assert 'Too long' in checker.check_strength('Ab1!xyzw').failed_checks

    @pytest.mark.parametrize('kwargs', [{'min_length': 0}, {'min_length': 10, 'max_length': 4}])
    def test_invalid_bounds(self, kwargs):
        with pytest.raises(ValueError):
            PasswordStrengthChecker(**kwargs)


class TestCharacterClasses:
    def test_all_classes_present(self, checker):
        result = checker.check_strength('Qw7!vKm2#Xw9$Lp4')
        assert result.failed_checks == []

    def test_missing_classes_reported(self, checker):
        result = checker.check_strength('qwertyuiop')
        assert 'Missing uppercase letters' in result.failed_checks
        assert 'Missing numbers' in result.failed_checks
        assert 'Missing special characters' in result.failed_checks

    def test_space_counts_as_special(self, checker):
        assert 'Contains special characters' in checker.check_strength('Qw7 vKm2 Xp').passed_checks

    def test_non_ascii_digits_do_not_count(self, checker):
        assert 'Missing numbers' in checker.check_strength('\u0663\u0664\u0665Aa!vKmx').failed_checks


class TestScoring:
    def test_max_score_is_reachable(self, checker):
        result = checker.check_strength('Qw7!vKm2#Xp9$Lr4')
        assert result.score == MAX_SCORE
        assert result.strength is StrengthLevel.VERY_STRONG
        assert result.verdict == 'Excellent password!'

    def test_score_never_negative(self, checker):
        assert checker.check_strength('aaaabcpassword').score == 0

    @pytest.mark.parametrize(
        'score,level',
        [
            (0, StrengthLevel.WEAK),
            (39, StrengthLevel.WEAK),
            (40, StrengthLevel.FAIR),
            (60, StrengthLevel.GOOD),
            (75, StrengthLevel.STRONG),
            (90, StrengthLevel.VERY_STRONG),
        ],
    )
    def test_strength_levels(self, checker, score, level):
        assert checker._get_strength_level(score) is level


class TestWeakPatterns:
    def test_common_word_penalized(self, checker):
        result = checker.check_strength('MyPassword1!X')
        assert 'Contains common patterns' in result.failed_checks

    def test_ascending_sequence(self, checker):
        assert checker._has_sequential_chars('Qw7abcKm!')

    def test_descending_sequence(self, checker):
        assert checker._has_sequential_chars('Qw7cba!Km')
        assert checker._has_sequential_chars('Qw321!Km')

    def test_no_cross_class_false_positive(self, checker):
        assert not checker._has_sequential_chars('Xy@ABq1!')
        assert not checker._has_sequential_chars('9AbZ!qr')

    def test_repeated_characters(self, checker):
        result = checker.check_strength('Qw7!vKmaaa')
        assert 'Contains repeated characters' in result.failed_checks
        assert not checker._has_repeated_chars('Qw7!vKmaa')

    def test_abc_penalized_once(self, checker):
        result = checker.check_strength('Qw7!vKabc')
        assert result.failed_checks.count('Contains sequential characters') == 1
        assert 'Contains common patterns' not in result.failed_checks


class TestInputValidation:
    @pytest.mark.parametrize('value', [None, 12345, b'bytes', ['a']])
    def test_non_string_rejected(self, checker, value):
        with pytest.raises(TypeError):
            checker.check_strength(value)

    def test_empty_string(self, checker):
        result = checker.check_strength('')
        assert result.score == 0
        assert result.strength is StrengthLevel.WEAK
