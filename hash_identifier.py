import argparse
import sys
from dataclasses import dataclass
from typing import Literal

Confidence = Literal['high', 'medium', 'low']

@dataclass (frozen=True,slots=True)
class HashCandidate:

    algorithm : str
    confidence : Confidence
    reason : str

HEX_CHARSET: frozenset[str] = frozenset("1234567890abcdefABCDEF")

_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)

PREFIX_RULES: list[tuple[str,str,str]] = [
     # Argon2 family — won the 2015 Password Hashing Competition
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),
    ("$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"),

    # bcrypt and its many variants — workhorse for the past 15 years
    ("$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"),
    ("$2b$", "bcrypt", "bcrypt PHC string, 2b variant (current)"),
    ("$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"),
    ("$2x$", "bcrypt", "bcrypt PHC string, 2x variant (legacy fix)"),

    # Unix crypt(3) family — what /etc/shadow uses on Linux
    ("$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512 (default on Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy, weak)"),

    # Apache htpasswd MD5 variant — same MD5 family as $1$ above but
    # with Apache's own salt-handling tweak. This is the format that
    # `htpasswd -m` emits by default, which makes it FAR more common
    # in the wild than the Unix $1$ form (every basic-auth tutorial
    # ends with one of these in a .htpasswd file)
    ("$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant (`htpasswd -m`)"),

    # yescrypt — newer Linux default in some distributions
    ("$y$", "yescrypt", "PHC string, modern Linux crypt successor"),

    # phpass — used by WordPress, phpBB, and other PHP apps
    ("$P$", "phpass", "WordPress / phpBB password hash"),
    ("$H$", "phpass", "phpBB-style phpass variant"),

    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "Drupal 7 PHC-style hash"),

    # scrypt as some implementations encode it
    ("$7$", "scrypt", "scrypt PHC-style hash"),

    # Django's default — recognizable by the algorithm name in the prefix
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default password hash"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "Django legacy password hash"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "Django bcrypt wrapper"),
    ("argon2$", "Django Argon2", "Django Argon2 wrapper"),

    # LDAP password schemes — base64 payload after the marker
    ("{SSHA}", "LDAP SSHA", "LDAP salted SHA-1 (base64 payload)"),
    ("{SHA}", "LDAP SHA", "LDAP SHA-1 (base64 payload)"),
    ("{SMD5}", "LDAP SMD5", "LDAP salted MD5 (base64 payload)"),
    ("{MD5}", "LDAP MD5", "LDAP MD5 (base64 payload)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP wrapping a crypt(3) hash"),
]

HEX_LENGTH_RULES: dict[int, list[str]] = {
    16: ["MySQL323", "CRC-64"],
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}

def _is_hex(text:str) -> bool:
    return bool(text) and all(c in HEX_CHARSET for c in text)


_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1

def _is_mysql5(text:str) -> bool:
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1:]
    return all(c in _HEX_UPPER_CHARSET for c in body)


_DESCRYPT_TOTAL_LENGTH = 13

def _is_descrypt(text:str) -> bool:
    if len(text) == _DESCRYPT_TOTAL_LENGTH and all(c in _DESCRYPT_CHARSET for c in text):
        return True

def identify(raw_input:str) -> list[HashCandidate]:
    text = raw_input.strip()

    if not text: 
        return []
    # Step 1: prefix match — first match wins
    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                HashCandidate(
                    algorithm=algorithm,
                    confidence='high',
                    reason=f"prefix `{prefix}` — {note}", 
                )]

    # Step 2: special shapes — NetNTLM, MySQL5, DES crypt
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        if len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4]):
            return [
                HashCandidate(
                    algorithm="NetNTLMv2",
                    confidence="high",
                    reason="NetNTLMv2 record, 32 hex chars in field 5",
                )
            ]
        if len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3]):
            return [
                HashCandidate(
                    algorithm="NetNTLMv1",
                    confidence="high",
                    reason="NetNTLMv1 record, 48 hex chars in field 4",
                )
            ]
    
    if _is_mysql5(text):
        return [
            HashCandidate(
                algorithm="MySQL5",
                confidence="high",
                reason="`*` + 40 uppercase hex chars",
            )
        ]

    if _is_descrypt(text):
        return [
            HashCandidate(
                algorithm="DES crypt",
                confidence="medium",
                reason="13 chars from the DES crypt alphabet",
            )
        ]
    
    # Step 3: hex + length lookup
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            confidence: Confidence = "medium" if index == 0 else "low"
            label = (
                "most likely candidate at this length"
                if index == 0
                else "also possible at this length"
            )
            candidates.append(
                HashCandidate(
                    algorithm=algorithm,
                    confidence=confidence,
                    reason=f"{len(text)} hex chars — {label}",
                )
            )
        return candidates


    # Step 4: generic PHC fallback
    if text.startswith("$"):
        rest = text[1:]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            if algo_name and all(c.isalnum() or c in "-_" for c in algo_name):
                return [
                    HashCandidate(
                        algorithm=f"PHC string ({algo_name})",
                        confidence="low",
                        reason=f"PHC-shaped string, unknown algorithm `{algo_name}`",
                    )
                ]
    
    # Step 5: shape hints — probably not a hash
    if text.startswith("eyJ"):
        return [
            HashCandidate(
                algorithm="JWT (not a hash)",
                confidence="low",
                reason="starts with eyJ — looks like a JWT, not a hash",
            )
        ]

    if any(c in text for c in "+/=") and len(text) > 8:
        return [
            HashCandidate(
                algorithm="Base64 blob (not a hash)",
                confidence="low",
                reason="contains base64 characters — probably not a hash",
            )
        ]

    # Step 6: give up
    return []


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashid",
        description="Identify what kind of hash a string is.",
    )
    parser.add_argument("hash", help="The hash string to identify.")
    parser.add_argument(
        "--top",
        "-n",
        type=int,
        default=5,
        help="Show only the top N candidates (default: 5).",
    )
    return parser

def _render_table(raw_input: str, candidates: list[HashCandidate]) -> None:
    print(f"Candidates for: {raw_input.strip()}")
    print(f"{'algorithm':<20} | {'confidence':<12} | reason")
    print("-" * 70)
    for candidate in candidates:
        print(
            f"{candidate.algorithm:<20} | {candidate.confidence:<12} | {candidate.reason}"
        )


def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()

    candidates = identify(args.hash)

    if not candidates:
        print("No identification possible.")
        return 1

    trimmed = candidates[:args.top]
    _render_table(args.hash, trimmed)

    if trimmed[0].confidence == "high":
        print("\nNext step: try the matching cracker for this algorithm.")
    return 0


if __name__ == "__main__":
    sys.exit(main())