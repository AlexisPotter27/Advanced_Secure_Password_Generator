import secrets
import string
import math


def calculate_entropy(length, pool_size):
    """Calculate password entropy."""
    return math.log2(pool_size ** length)


def generate_advanced_password(length = 10, use_upper = True, use_lower = True, use_digits = True,
                               use_special = True, exclude_chars = ""):
    """
    Generate a secure password with customizable options.

    Parameters:
    - length: Length of the password.
    - use_upper: Include uppercase letters.
    - use_lower: Include lowercase letters.
    - use_digits: Include digits.
    - use_special: Include special characters.
    - exclude_chars: Characters to exclude from the password.

    Returns:
    - A secure password and its entropy.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 characters.")

    # Define character pools
    char_pools = {
        'upper': string.ascii_uppercase if use_upper else "",
        'lower': string.ascii_lowercase if use_lower else "",
        'digits': string.digits if use_digits else "",
        'special': string.punctuation if use_special else "",
    }

    # Combine pools and apply exclusions
    all_chars = "".join(char_pools.values())
    all_chars = "".join(c for c in all_chars if c not in exclude_chars)

    if not all_chars:
        raise ValueError("No valid characters available to generate password.")

    # Ensure at least one character from each enabled pool
    password = []

    if use_upper:
        password.append(secrets.choice(string.ascii_uppercase.replace(exclude_chars, "")))
    if use_lower:
        password.append(secrets.choice(string.ascii_lowercase.replace(exclude_chars, "")))
    if use_digits:
        password.append(secrets.choice(string.digits.replace(exclude_chars, "")))
    if use_special:
        password.append(secrets.choice(string.punctuation.replace(exclude_chars, "")))

    # Fill the rest of the password length with random characters
    password += [secrets.choice(all_chars) for _ in range(length - len(password))]

    # Shuffle to prevent predictable patterns
    secrets.SystemRandom().shuffle(password)

    # Calculate password entropy
    entropy = calculate_entropy(length, len(all_chars))

    return ''.join(password), entropy


# Example Usage:
length = 20
password, entropy = generate_advanced_password(length = length, use_upper = True, use_lower = True,
                                               use_digits = True, use_special = True, exclude_chars = "lI1O0")
print(f"Generated Secure Password: {password}")
print(f"Password Entropy: {entropy:.2f} bits")
