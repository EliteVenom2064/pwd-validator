# pwd-validator

A Python password strength validator with detailed feedback and scoring.

## Features

- 🔒 **Comprehensive Validation** - Checks length, character variety, and common patterns
- 📊 **Detailed Scoring** - Scores passwords from 0-100 with 5 strength levels
- 💡 **Smart Feedback** - Provides specific suggestions for improvement
- ⚡ **Fast & Lightweight** - Minimal dependencies, optimized performance
- 🧪 **Well Tested** - Comprehensive unit test coverage

## Strength Criteria

The checker evaluates passwords based on:

- **Length** (8-128 characters recommended)
- **Character Variety** - Lowercase, uppercase, numbers, special characters
- **Common Patterns** - Blocks weak passwords like "password123"
- **Sequential Characters** - Detects patterns like "abc" or "123"

### Strength Levels

| Level | Score | Notes |
|-------|-------|-------|
| 🔴 **Weak** | 0-39 | Very insecure |
| 🟡 **Fair** | 40-59 | Acceptable but could be stronger |
| 🟢 **Good** | 60-74 | Reasonably secure |
| 🟢 **Strong** | 75-89 | Very secure |
| 🟢 **Very Strong** | 90-100 | Excellent security |

## Installation

```bash
# Clone the repository
git clone https://github.com/EliteVenom2064/pwd-validator.git
cd pwd-validator

# No external dependencies required (uses only Python stdlib)
```

## Quick Start

```python
from password_strength_checker import PasswordStrengthChecker

checker = PasswordStrengthChecker()
result = checker.check_strength("MyP@ssw0rd2024!")

print(f"Strength: {result.strength.value}")
print(f"Score: {result.score}/100")
print(f"Feedback: {result.feedback}")
```

## Usage Examples

### Basic Usage

```python
from password_strength_checker import PasswordStrengthChecker

checker = PasswordStrengthChecker()

# Check a password
result = checker.check_strength("P@ssw0rd123")

print(f"Password Strength: {result.strength.value} ({result.score}/100)")
print(f"Passed checks: {result.passed_checks}")
print(f"Failed checks: {result.failed_checks}")
print(f"Suggestions: {result.feedback}")
```

**Output:**
```
Password Strength: good (65/100)
Passed checks: ['Meets minimum length', 'Contains lowercase letters', 'Contains uppercase letters', 'Contains numbers', 'Contains special characters']
Failed checks: []
Suggestions: ['Good password, but could be stronger']
```

### Interactive Checker

```bash
python examples/interactive_checker.py
```

This launches an interactive CLI tool where you can test multiple passwords.

## API Reference

### `PasswordStrengthChecker`

```python
checker = PasswordStrengthChecker(min_length=8, max_length=128)
```

**Methods:**

- `check_strength(password: str) -> StrengthResult` - Validates and scores a password

**Parameters:**
- `min_length` (int, default=8) - Minimum password length
- `max_length` (int, default=128) - Maximum password length

### `StrengthResult`

Returned object with the following attributes:

- `score` (int) - Password strength score (0-100)
- `strength` (StrengthLevel) - Enum: WEAK, FAIR, GOOD, STRONG, VERY_STRONG
- `feedback` (List[str]) - Suggestions for improvement
- `passed_checks` (List[str]) - List of passed validation checks
- `failed_checks` (List[str]) - List of failed validation checks

## Testing

```bash
# Run all tests
python -m pytest tests/

# Run with verbose output
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_password_checker.py::TestPasswordLength -v
```

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Future Enhancements

- [ ] Integration with HIBP (Have I Been Pwned) API for breach detection
- [ ] Support for passphrase validation
- [ ] Custom validation rules
- [ ] Web interface (Flask/FastAPI)
- [ ] Entropy calculation
- [ ] Integration with password managers

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**EliteVenom2064**

## Disclaimer

This tool is designed for educational purposes and to help users create stronger passwords. Always follow your organization's password policy and security guidelines.
