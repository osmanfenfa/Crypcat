import hashlib
import itertools
import math
import re
import secrets
import string
import time
from typing import Optional
from cryptography.fernet import Fernet

# Common password list for strength checking
COMMON_PASSWORDS = {
    "admin123", "welcome123", "letmein123", "qwertyuiop", "asdfghjkl",
    "zxcvbnm", "1q2w3e4r", "1qaz2wsx", "qazwsx", "password!", "pass123",
    "test123", "guest", "guest123", "user", "user123", "administrator",
    "adminadmin", "root123", "system", "support", "demo", "temp",
    "temp123", "default123", "changeme123", "newpassword", "oldpassword",
    "passw0rd", "p@ssword", "p@ssw0rd", "123123", "321321", "112233",
    "123qwe", "qwe123", "q1w2e3r4", "abc123456", "password2023",
    "password2024", "password2025", "welcome1", "welcome2", "welcome2024",
    "iloveyou1", "iloveyou2", "iloveu", "lovely", "loveme", "babygirl",
    "babyboy", "freedom", "whatever", "qwerty1", "qwerty12", "qwertyui",
    "asdf1234", "asdfgh", "zxcvbn", "987654321", "87654321", "7654321",
    "11111111", "222222", "333333", "444444", "555555", "666666",
    "7777777", "888888", "999999", "121212", "101010", "202020",
    "admin1", "admin2", "admin2024", "rootroot", "server", "database",
    "mysql", "oracle", "postgres", "docker", "kubernetes", "ubuntu",
    "linux", "windows", "macbook", "apple123", "google", "facebook",
    "twitter", "instagram", "linkedin", "snapchat", "tiktok",
    "letme1n", "opensesame", "access", "secure", "security",
    "trustme", "trustnoone", "anonymous", "hacker", "hackme",
    "cyber", "cyber123", "password@", "admin@", "root@", "user@123"
}

# Built-in wordlist for hash cracking 
BUILTIN_WORDLIST = [
    "password2024", "password2025", "admin123", "admin2024",
    "welcome123", "welcome2025", "login123", "user123",
    "guest123", "test1234", "passw0rd", "p@ssword", "1q2w3e4r", 
    "1qaz2wsx", "qazwsx", "qweasdzxc", "asdfghjkl", "zxcvbnm", 
    "qwertyuiop", "poiuytrewq", "aaaaaa", "bbbbbb", "ababab", 
    "abcabc", "121212", "123123123", "111222", "000111", "999999",
    "john", "john123", "mary", "mary123", "james", "james123", 
    "daniel", "daniel1", "paul", "paul123", "linda", "linda123",
    "naruto", "naruto123", "pokemon", "pokemon1", "dragonball", 
    "goku", "vegeta", "onepiece", "luffy", "zoro", "starwars", "matrix",
    "adminadmin", "rootroot", "server123", "database", "mysql", "oracle", 
    "postgres", "ubuntu", "linux123", "windows123", "docker123", "kubernetes123",
    "january", "february", "march", "april", "may123", "june123", "july123", 
    "august","september", "october", "november", "december",
    "summer2024", "summer2025", "winter2024", "spring2025", "autumn2024",
    "iloveu", "iloveme", "lovely123", "babygirl", "babyboy", "mybaby", "sweetheart",
    "soccer", "soccer123", "basketball", "football123", "tennis", "cricket",
    "qwerty1", "qwerty12", "asdf1234", "zxcvbn123", "password!", "admin!",
    "root@", "user@", "guest@123"
]

# Supported hash algorithms
HASH_ALGOS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

# Charsets for brute force simulation
CHARSETS = {
    "digits":       string.digits,
    "lowercase":    string.ascii_lowercase,
    "uppercase":    string.ascii_uppercase,
    "alphanumeric": string.ascii_letters + string.digits,
    "full":         string.ascii_letters + string.digits + "!@#$%^&*",
}

GUESSES_PER_SECOND = 1_000_000_000  # ~1 billion (modern GPU estimate)


# PASSWORD AUDITOR
def audit_password(password: str) -> dict:
    """
    Comprehensive password strength analysis.
    Returns score (0-100), strength label, entropy, and actionable feedback.
    """
    issues: list[str] = []
    suggestions: list[str] = []
    score = 0

    # Length
    length = len(password)
    if length < 8:
        issues.append("Too short — under 8 characters")
        suggestions.append("Use at least 12 characters for real security")
    elif length < 12:
        score += 10
        suggestions.append("Increase to 16+ characters for a stronger password")
    elif length < 16:
        score += 20
    else:
        score += 30

    # Character variety 
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_lower   = bool(re.search(r'[a-z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^A-Za-z0-9]', password))
    if has_upper:
        score += 10
    else:
        issues.append("No uppercase letters")
        suggestions.append("Add uppercase letters (A–Z)")

    if has_lower:
        score += 10
    else:
        issues.append("No lowercase letters")
        suggestions.append("Add lowercase letters (a–z)")

    if has_digit:
        score += 10
    else:
        issues.append("No digits")
        suggestions.append("Include numbers (0–9)")

    if has_special:
        score += 20
    else:
        issues.append("No special characters")
        suggestions.append("Add symbols such as !@#$%^&*")

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        issues.append("Extremely common password — appears in every cracking dictionary")
        suggestions.append("Avoid dictionary words and well-known patterns")
        score = max(0, score - 40)

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters (e.g. aaa, 111)")
        suggestions.append("Avoid repeating the same character consecutively")
        score = max(0, score - 10)

    # Sequential characters 
    seq_pattern = (
        r'(012|123|234|345|456|567|678|789|890|'
        r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|'
        r'jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|'
        r'stu|tuv|uvw|vwx|wxy|xyz)'
    )
    if re.search(seq_pattern, password.lower()):
        issues.append("Contains sequential characters (e.g. 123, abc)")
        suggestions.append("Avoid predictable sequences")
        score = max(0, score - 10)

    # Keyboard walk check
    keyboard_walks = ["qwerty", "asdf", "zxcv", "qazwsx", "1qaz", "2wsx"]
    if any(walk in password.lower() for walk in keyboard_walks):
        issues.append("Contains keyboard walk pattern (e.g. qwerty, asdf)")
        suggestions.append("Avoid keyboard patterns")
        score = max(0, score - 10)

    # Entropy calculation
    charset_size = 0
    if has_lower:   charset_size += 26
    if has_upper:   charset_size += 26
    if has_digit:   charset_size += 10
    if has_special: charset_size += 32
    entropy = length * math.log2(charset_size) if charset_size > 0 else 0

    score = min(100, max(0, score))
    if score >= 80:   strength = "Strong"
    elif score >= 60: strength = "Good"
    elif score >= 40: strength = "Moderate"
    elif score >= 20: strength = "Weak"
    else:             strength = "Very Weak"

    # Crack time estimate
    combinations = charset_size ** length if charset_size > 0 else 1
    crack_seconds = combinations / GUESSES_PER_SECOND
    crack_time = _format_time(crack_seconds)

    return {
        "score": score,
        "strength": strength,
        "entropy_bits": round(entropy, 2),
        "length": length,
        "estimated_crack_time": crack_time,
        "has_uppercase": has_upper,
        "has_lowercase": has_lower,
        "has_digits": has_digit,
        "has_special": has_special,
        "issues": issues,
        "suggestions": suggestions,
    }


# HASH IDENTIFIER
HASH_PATTERNS = [
    (r'^[a-f0-9]{8}$',   "CRC-32"),
    (r'^[a-f0-9]{32}$',  "MD5"),
    (r'^[a-f0-9]{40}$',  "SHA-1"),
    (r'^[a-f0-9]{56}$',  "SHA-224"),
    (r'^[a-f0-9]{64}$',  "SHA-256"),
    (r'^[a-f0-9]{96}$',  "SHA-384"),
    (r'^[a-f0-9]{128}$', "SHA-512"),
    (r'^\$2[aby]\$.{56}$',   "bcrypt"),
    (r'[a-zA-Z0-9+/]{22}==', "bcrypt (Base64)"),
    (r'^\$1\$.+\$.+$',       "MD5-Crypt"),
    (r'^\$5\$.+\$.+$',       "SHA-256-Crypt"),
    (r'^\$6\$.+\$.+$',       "SHA-512-Crypt"),
    (r'^[a-f0-9]{48}$',      "Tiger-192"),
    (r'^[a-zA-Z0-9+/]{24}=$', "MD5 (Base64)"),
]

HASH_DESCRIPTIONS = {
    "MD5":         "Fast, widely used — considered cryptographically broken. Common in older systems.",
    "SHA-1":       "Deprecated since 2011. Vulnerable to collision attacks.",
    "SHA-224":     "Truncated variant of SHA-256. Rarely used in practice.",
    "SHA-256":     "Current standard. Part of SHA-2 family. Widely trusted.",
    "SHA-384":     "Truncated SHA-512. Offers extra security margin.",
    "SHA-512":     "Very strong. 512-bit output. Recommended for passwords when bcrypt isn't used.",
    "bcrypt":      "Password hashing standard. Includes salt. Recommended for passwords.",
    "MD5-Crypt":   "MD5-based Unix crypt. Outdated — prefer bcrypt/SHA-512-Crypt.",
    "SHA-256-Crypt": "Unix crypt using SHA-256. Modern and acceptable.",
    "SHA-512-Crypt": "Unix crypt using SHA-512. Recommended for Unix password storage.",
    "CRC-32":      "Checksum only — not a cryptographic hash. Trivially reversible.",
    "Tiger-192":   "Optimised for 64-bit platforms. Rarely seen in modern software.",
}

def identify_hash(hash_str: str) -> dict:
    """Identify possible hash algorithm(s) from a hash string."""
    hash_str = hash_str.strip()
    possible = []
    for pattern, name in HASH_PATTERNS:
        if re.match(pattern, hash_str, re.IGNORECASE):
            possible.append({
                "type": name,
                "description": HASH_DESCRIPTIONS.get(name, ""),
            })
    return {
        "hash": hash_str,
        "length": len(hash_str),
        "possible_types": possible if possible else [{"type": "Unknown / Custom", "description": "Does not match any known hash pattern."}],
    }


# HASH CRACKER (wordlist)
def crack_hash(hash_str: str, hash_type: str, custom_words: list[str] | None = None) -> dict:
    """
    Try to crack a hash using the built-in wordlist plus any custom words provided.
    Educational use only — never use against systems you do not own.
    """
    hash_str = hash_str.strip().lower()
    algo_key = hash_type.lower().replace("-", "").replace("_", "")
    algo = HASH_ALGOS.get(algo_key)

    if not algo:
        return {"cracked": False, "error": f"Unsupported hash type: {hash_type}. Supported: {list(HASH_ALGOS.keys())}"}

    wordlist = (custom_words or []) + BUILTIN_WORDLIST
    start = time.time()
    for idx, word in enumerate(wordlist):
        candidate = algo(word.encode()).hexdigest()
        if candidate == hash_str:
            return {
                "cracked": True,
                "plaintext": word,
                "hash_type": hash_type,
                "attempts": idx + 1,
                "time_seconds": round(time.time() - start, 4),
            }

    return {
        "cracked": False,
        "hash_type": hash_type,
        "attempts": len(wordlist),
        "time_seconds": round(time.time() - start, 4),
        "message": "Not found in wordlist. Try supplying custom words or use brute-force simulation.",
    }


# ENCRYPTION / DECRYPTION  (Fernet symmetric)
def generate_fernet_key() -> str:
    """Generate a new Fernet (AES-128-CBC + HMAC-SHA256) key."""
    return Fernet.generate_key().decode()

def encrypt_data(data: bytes, key: str) -> dict:
    """Encrypt bytes with a Fernet key. Returns base64-encoded token."""
    try:
        f = Fernet(key.encode() if isinstance(key, str) else key)
        token = f.encrypt(data)
        return {
            "success": True,
            "encrypted": token.decode(),
            "original_size_bytes": len(data),
            "encrypted_size_bytes": len(token),
            "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def decrypt_data(token: str, key: str) -> dict:
    """Decrypt a Fernet token with the provided key."""
    try:
        f = Fernet(key.encode() if isinstance(key, str) else key)
        raw = f.decrypt(token.strip().encode() if isinstance(token, str) else token)
        return {
            "success": True,
            "decrypted": raw.decode(errors="replace"),
            "size_bytes": len(raw),
        }
    except Exception:
        return {"success": False, "error": "Decryption failed — wrong key or corrupted data."}


# BRUTE FORCE SIMULATION
def brute_force_simulate(
    hash_str: str,
    hash_type: str,
    max_length: int,
    charset_name: str,
    max_attempts: int = 200_000,
) -> dict:
    """
    Simulate a brute-force attack on a hash.
    Attempts up to max_attempts combinations; remainder is estimated.
    Educational OR on-your-own-systems use only.
    """
    hash_str  = hash_str.strip().lower()
    algo_key  = hash_type.lower().replace("-", "").replace("_", "")
    algo      = HASH_ALGOS.get(algo_key)
    charset   = CHARSETS.get(charset_name, string.ascii_lowercase)

    if not algo:
        return {"error": f"Unsupported hash type: {hash_type}"}

    total_combinations = sum(len(charset) ** i for i in range(1, max_length + 1))
    estimated_seconds  = total_combinations / GUESSES_PER_SECOND

    attempts = 0
    found    = None
    start    = time.time()
    outer_break = False
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            if attempts >= max_attempts:
                outer_break = True
                break
            word = "".join(combo)
            attempts += 1
            if algo(word.encode()).hexdigest() == hash_str:
                found = word
                outer_break = True
                break
        if outer_break:
            break

    elapsed = round(time.time() - start, 4)

    return {
        "cracked": found is not None,
        "plaintext": found,
        "hash_type": hash_type,
        "charset_name": charset_name,
        "charset_size": len(charset),
        "max_length_tested": max_length,
        "total_keyspace": total_combinations,
        "attempts_made": attempts,
        "elapsed_seconds": elapsed,
        "estimated_full_crack_time": _format_time(estimated_seconds),
        "guesses_per_second_gpu_estimate": GUESSES_PER_SECOND,
        "simulation_cap": max_attempts,
        "note": f"Live simulation capped at {max_attempts:,} attempts. Full keyspace stats are theoretical.",
    }


# PASSWORD GENERATOR
def generate_password(
    length: int = 16,
    require_upper: bool = True,
    require_lower: bool = True,
    require_digits: bool = True,
    require_special: bool = True,
    exclude_ambiguous: bool = False,
    custom_special: Optional[str] = None,
) -> dict:
    """
    Generate a cryptographically secure password that satisfies the given policy.
    Uses secrets.SystemRandom for CSPRNG-backed generation.
    """
    if length < 4:
        return {"error": "Minimum password length is 4"}
    if length > 256:
        return {"error": "Maximum password length is 256"}

    lower_pool   = "abcdefghjkmnpqrstuvwxyz"   if exclude_ambiguous else string.ascii_lowercase
    upper_pool   = "ABCDEFGHJKMNPQRSTUVWXYZ"   if exclude_ambiguous else string.ascii_uppercase
    digit_pool   = "23456789"                   if exclude_ambiguous else string.digits
    special_pool = custom_special or "!@#$%^&*()-_=+[]{}|;:,.<>?"
    pool:            str        = ""
    required_chars: list[str]  = []
    if require_lower:
        pool += lower_pool
        required_chars.append(secrets.choice(lower_pool))
    if require_upper:
        pool += upper_pool
        required_chars.append(secrets.choice(upper_pool))
    if require_digits:
        pool += digit_pool
        required_chars.append(secrets.choice(digit_pool))
    if require_special:
        pool += special_pool
        required_chars.append(secrets.choice(special_pool))

    if not pool:
        return {"error": "At least one character type must be selected"}

    remaining       = [secrets.choice(pool) for _ in range(length - len(required_chars))]
    password_chars  = required_chars + remaining
    secrets.SystemRandom().shuffle(password_chars)
    password        = "".join(password_chars)
    audit = audit_password(password)

    return {
        "password":     password,
        "length":       length,
        "strength":     audit["strength"],
        "score":        audit["score"],
        "entropy_bits": audit["entropy_bits"],
        "estimated_crack_time": audit["estimated_crack_time"],
        "policy": {
            "require_upper":      require_upper,
            "require_lower":      require_lower,
            "require_digits":     require_digits,
            "require_special":    require_special,
            "exclude_ambiguous":  exclude_ambiguous,
        },
    }


# HELPERS
def _format_time(seconds: float) -> str:
    if seconds < 0.001:  return "< 1 millisecond"
    if seconds < 1:      return f"{seconds*1000:.0f} milliseconds"
    if seconds < 60:     return f"{seconds:.1f} seconds"
    if seconds < 3_600:  return f"{seconds/60:.1f} minutes"
    if seconds < 86_400: return f"{seconds/3600:.1f} hours"
    if seconds < 2_592_000:  return f"{seconds/86400:.1f} days"
    if seconds < 31_536_000: return f"{seconds/2592000:.1f} months"
    years = seconds / 31_536_000
    if years > 1e12: return "longer than the age of the universe"
    return f"{years:,.2f} years"