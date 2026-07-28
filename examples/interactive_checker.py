"""Interactive CLI for trying out the password strength checker."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from password_strength_checker import PasswordStrengthChecker  # noqa: E402


def main() -> None:
    checker = PasswordStrengthChecker()
    print('Password strength checker (empty input or Ctrl-D to quit)\n')

    while True:
        try:
            password = input('Password: ')
        except EOFError:
            print()
            break
        if not password:
            break

        result = checker.check_strength(password)
        print(f'  Strength: {result.strength.value} ({result.score}/100)')
        for check in result.passed_checks:
            print(f'  + {check}')
        for check in result.failed_checks:
            print(f'  - {check}')
        for suggestion in result.feedback:
            print(f'  > {suggestion}')
        if result.verdict:
            print(f'  {result.verdict}')
        print()


if __name__ == '__main__':
    main()
