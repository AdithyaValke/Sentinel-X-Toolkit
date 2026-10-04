import re
from typing import Any, Dict, List, Optional, Tuple

MAX_HASH_INPUT_LENGTH = 4096
MAX_HASH_LINES = 50

HEX_PATTERNS = {
    8: [
        {"algorithm": "CRC32", "hashcat_mode": "11500", "description": "8 hex characters (32-bit cyclic redundancy checksum, non-cryptographic)."},
        {"algorithm": "CRC32b", "hashcat_mode": "11500", "description": "8 hex characters (alternative endianness variant)."},
    ],
    16: [
        {"algorithm": "MySQL 3.23", "hashcat_mode": "200", "description": "16 hex characters (historic MySQL password hash)."},
    ],
    32: [
        {"algorithm": "MD5", "hashcat_mode": "0", "description": "32 hex characters, standard 128-bit digest."},
        {"algorithm": "NTLM", "hashcat_mode": "1000", "description": "32 hex characters (Windows NT LAN Manager; MD4 of UTF-16LE, identical appearance to MD5)."},
        {"algorithm": "MD4", "hashcat_mode": "900", "description": "32 hex characters, 128-bit predecessor to MD5."},
        {"algorithm": "LM", "hashcat_mode": "3000", "description": "32 hex characters (LAN Manager hash; split DES pairs, commonly uppercase)."},
    ],
    40: [
        {"algorithm": "SHA-1", "hashcat_mode": "100", "description": "40 hex characters, standard 160-bit digest."},
        {"algorithm": "MySQL 4.1+/5+", "hashcat_mode": "300", "description": "40 hex characters (SHA-1 double hash, often stored without leading asterisk)."},
        {"algorithm": "RIPEMD-160", "hashcat_mode": "6000", "description": "40 hex characters, 160-bit cryptographic hash."},
    ],
    56: [
        {"algorithm": "SHA-224", "hashcat_mode": "1300", "description": "56 hex characters, 224-bit SHA-2 family digest."},
        {"algorithm": "SHA-512/224", "hashcat_mode": None, "description": "56 hex characters (truncated SHA-512 variant)."},
    ],
    64: [
        {"algorithm": "SHA-256", "hashcat_mode": "1400", "description": "64 hex characters, standard 256-bit SHA-2 digest."},
        {"algorithm": "SHA-512/256", "hashcat_mode": None, "description": "64 hex characters (truncated SHA-512 variant)."},
        {"algorithm": "SHA3-256", "hashcat_mode": "17400", "description": "64 hex characters, Keccak/SHA-3 standard 256-bit digest."},
        {"algorithm": "BLAKE2s-256", "hashcat_mode": None, "description": "64 hex characters, BLAKE2s 256-bit digest."},
    ],
    96: [
        {"algorithm": "SHA-384", "hashcat_mode": "10800", "description": "96 hex characters, 384-bit SHA-2 digest."},
        {"algorithm": "SHA3-384", "hashcat_mode": "17500", "description": "96 hex characters, Keccak/SHA-3 384-bit digest."},
    ],
    128: [
        {"algorithm": "SHA-512", "hashcat_mode": "1700", "description": "128 hex characters, standard 512-bit SHA-2 digest."},
        {"algorithm": "SHA3-512", "hashcat_mode": "17600", "description": "128 hex characters, Keccak/SHA-3 512-bit digest."},
        {"algorithm": "BLAKE2b-512", "hashcat_mode": None, "description": "128 hex characters, BLAKE2b 512-bit digest."},
    ],
}


def detect_character_format(val: str) -> str:
    """Detect the general character encoding / format of the candidate hash."""
    if re.fullmatch(r"^[a-fA-F0-9]+$", val):
        return "hexadecimal"
    if val.startswith(("$2a$", "$2b$", "$2y$", "$2x$")):
        return "modular_crypt_bcrypt"
    if val.startswith("$argon2"):
        return "modular_crypt_argon2"
    if val.startswith(("$1$", "$5$", "$6$")):
        return "modular_crypt_unix"
    if val.startswith(("$7$", "$scrypt$")):
        return "modular_crypt_scrypt"
    if val.startswith("*") and re.fullmatch(r"^\*[a-fA-F0-9]{40}$", val):
        return "mysql_password_hash"
    if re.fullmatch(r"^[a-zA-Z0-9./]+$", val):
        return "crypt_charset"
    return "alphanumeric_or_symbols"


def identify_single_hash(raw_hash: str) -> Dict[str, Any]:
    """Analyze a single hash string deterministically.

    Returns structured analysis dictionary including candidate algorithms,
    evidence levels, ambiguity indicators, and user-facing summary strings.
    """
    cleaned = raw_hash.strip()
    if not cleaned:
        raise ValueError("Hash string cannot be empty")

    if len(cleaned) > MAX_HASH_INPUT_LENGTH:
        raise ValueError(f"Hash input exceeds maximum allowed length of {MAX_HASH_INPUT_LENGTH} characters")

    length = len(cleaned)
    char_format = detect_character_format(cleaned)
    candidates: List[Dict[str, Any]] = []
    display_result = "Unknown Hash Format. Check length and character set."

    # 1. Hexadecimal digests
    if re.fullmatch(r"^[a-fA-F0-9]+$", cleaned):
        if length == 32:
            display_result = "Matches: MD5 (Hashcat: 0), NTLM (Hashcat: 1000), or MD4 (Hashcat: 900)"
            candidates = [
                {
                    "algorithm": "MD5",
                    "hashcat_mode": "0",
                    "evidence": "length_and_format_match",
                    "explanation": "Input is 32 hexadecimal characters (128-bit), consistent with a raw MD5 digest.",
                },
                {
                    "algorithm": "NTLM",
                    "hashcat_mode": "1000",
                    "evidence": "length_and_format_match",
                    "explanation": "NTLM representations are also 32 hexadecimal characters (MD4 of UTF-16LE).",
                },
                {
                    "algorithm": "MD4",
                    "hashcat_mode": "900",
                    "evidence": "length_and_format_match",
                    "explanation": "MD4 produces 32 hexadecimal characters; common in legacy systems and protocols.",
                },
                {
                    "algorithm": "LM",
                    "hashcat_mode": "3000",
                    "evidence": "length_and_format_match",
                    "explanation": "LAN Manager (LM) hashes are 32 hexadecimal characters (two 7-byte DES halves).",
                },
            ]
        elif length == 40:
            display_result = "Matches: SHA-1 (Hashcat: 100)"
            candidates = [
                {
                    "algorithm": "SHA-1",
                    "hashcat_mode": "100",
                    "evidence": "length_and_format_match",
                    "explanation": "Input is 40 hexadecimal characters (160-bit), consistent with a raw SHA-1 digest.",
                },
                {
                    "algorithm": "MySQL 4.1+/5+",
                    "hashcat_mode": "300",
                    "evidence": "length_and_format_match",
                    "explanation": "MySQL 4.1+ double-SHA1 hashes can be stored as 40 hexadecimal characters without the leading asterisk.",
                },
                {
                    "algorithm": "RIPEMD-160",
                    "hashcat_mode": "6000",
                    "evidence": "length_and_format_match",
                    "explanation": "RIPEMD-160 produces a 40 hexadecimal character digest.",
                },
            ]
        elif length == 64:
            display_result = "Matches: SHA-256 (Hashcat: 1400)"
            candidates = [
                {
                    "algorithm": "SHA-256",
                    "hashcat_mode": "1400",
                    "evidence": "length_and_format_match",
                    "explanation": "Input is 64 hexadecimal characters (256-bit), consistent with a raw SHA-256 digest.",
                },
                {
                    "algorithm": "SHA-512/256",
                    "hashcat_mode": None,
                    "evidence": "length_and_format_match",
                    "explanation": "SHA-512/256 is a truncated SHA-512 variant that produces a 64 hexadecimal character output.",
                },
                {
                    "algorithm": "SHA3-256",
                    "hashcat_mode": "17400",
                    "evidence": "length_and_format_match",
                    "explanation": "SHA3-256 (Keccak family) also produces 64 hexadecimal characters.",
                },
            ]
        elif length == 128:
            display_result = "Matches: SHA-512 (Hashcat: 1700)"
            candidates = [
                {
                    "algorithm": "SHA-512",
                    "hashcat_mode": "1700",
                    "evidence": "length_and_format_match",
                    "explanation": "Input is 128 hexadecimal characters (512-bit), consistent with a raw SHA-512 digest.",
                },
                {
                    "algorithm": "SHA3-512",
                    "hashcat_mode": "17600",
                    "evidence": "length_and_format_match",
                    "explanation": "SHA3-512 produces a 128 hexadecimal character digest.",
                },
                {
                    "algorithm": "BLAKE2b-512",
                    "hashcat_mode": None,
                    "evidence": "length_and_format_match",
                    "explanation": "BLAKE2b-512 produces a 128 hexadecimal character digest.",
                },
            ]
        elif length in HEX_PATTERNS:
            entry = HEX_PATTERNS[length]
            primary = entry[0]
            display_result = f"Matches: {primary['algorithm']}" + (f" (Hashcat: {primary['hashcat_mode']})" if primary["hashcat_mode"] else "")
            candidates = [
                {
                    "algorithm": item["algorithm"],
                    "hashcat_mode": item["hashcat_mode"],
                    "evidence": "length_and_format_match",
                    "explanation": f"Input is {length} hexadecimal characters, consistent with {item['algorithm']} ({item['description']}).",
                }
                for item in entry
            ]

    # 2. bcrypt format ($2a$, $2b$, $2y$, $2x$ and length 60)
    elif re.match(r"^\$2[abyx]\$[0-9]{2}\$[./A-Za-z0-9]{53}$", cleaned):
        display_result = "Matches: bcrypt (Hashcat: 3200)"
        candidates = [
            {
                "algorithm": "bcrypt",
                "hashcat_mode": "3200",
                "evidence": "structured_prefix_and_format",
                "explanation": "Matches standard modular crypt bcrypt format ($2a$, $2b$, or $2y$, 2-digit cost parameter, and 53-character salt/hash base64 string).",
            }
        ]
    elif cleaned.startswith(("$2a$", "$2b$", "$2y$")) and length == 60:
        display_result = "Matches: bcrypt (Hashcat: 3200)"
        candidates = [
            {
                "algorithm": "bcrypt",
                "hashcat_mode": "3200",
                "evidence": "structured_prefix_and_format",
                "explanation": "Input starts with a standard bcrypt prefix ($2a$, $2b$, or $2y$) and has the expected total length of 60 characters.",
            }
        ]

    # 3. Argon2 format
    elif cleaned.startswith("$argon2"):
        display_result = "Matches: Argon2 (Hashcat: 25300)"
        argon_variant = "Argon2"
        if cleaned.startswith("$argon2id"):
            argon_variant = "Argon2id"
        elif cleaned.startswith("$argon2i"):
            argon_variant = "Argon2i"
        elif cleaned.startswith("$argon2d"):
            argon_variant = "Argon2d"

        candidates = [
            {
                "algorithm": argon_variant,
                "hashcat_mode": "25300",
                "evidence": "structured_prefix_and_format",
                "explanation": f"Input begins with the recognizable ${argon_variant.lower()}$ modular crypt prefix and parameter encoding.",
            }
        ]

    # 4. scrypt format ($7$ or $scrypt$)
    elif cleaned.startswith(("$7$", "$scrypt$")):
        display_result = "Matches: scrypt (Hashcat: 8900)"
        candidates = [
            {
                "algorithm": "scrypt",
                "hashcat_mode": "8900",
                "evidence": "structured_prefix_and_format",
                "explanation": "Input uses a documented modular crypt format for scrypt password hashing ($7$ or $scrypt$).",
            }
        ]

    # 5. Unix crypt formats ($1$ MD5-crypt, $5$ SHA-256-crypt, $6$ SHA-512-crypt, or 13-char DES crypt)
    elif re.match(r"^\$1\$[./a-zA-Z0-9]{1,8}\$[./a-zA-Z0-9]{22}$", cleaned):
        display_result = "Matches: MD5-crypt (Hashcat: 500)"
        candidates = [
            {
                "algorithm": "MD5-crypt (Unix)",
                "hashcat_mode": "500",
                "evidence": "structured_prefix_and_format",
                "explanation": "Input matches the standard Unix $1$ MD5-crypt format.",
            }
        ]
    elif re.match(r"^\$5\$(rounds=\d+\$)?[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{43}$", cleaned):
        display_result = "Matches: SHA-256-crypt (Hashcat: 7400)"
        candidates = [
            {
                "algorithm": "SHA-256-crypt (Unix)",
                "hashcat_mode": "7400",
                "evidence": "structured_prefix_and_format",
                "explanation": "Input matches the standard Unix $5$ SHA-256-crypt format with optional rounds specification.",
            }
        ]
    elif re.match(r"^\$6\$(rounds=\d+\$)?[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{86}$", cleaned):
        display_result = "Matches: SHA-512-crypt (Hashcat: 1800)"
        candidates = [
            {
                "algorithm": "SHA-512-crypt (Unix)",
                "hashcat_mode": "1800",
                "evidence": "structured_prefix_and_format",
                "explanation": "Input matches the standard Unix $6$ SHA-512-crypt format with optional rounds specification.",
            }
        ]
    elif length == 13 and re.fullmatch(r"^[a-zA-Z0-9./]{13}$", cleaned):
        display_result = "Matches: DES-crypt (Hashcat: 1500)"
        candidates = [
            {
                "algorithm": "DES-crypt (Unix crypt)",
                "hashcat_mode": "1500",
                "evidence": "length_and_format_match",
                "explanation": "13 characters from traditional crypt64 character set ([a-zA-Z0-9./]), 2 salt characters followed by 11 ciphertext characters.",
            }
        ]

    # 6. MySQL 4.1+/5+ prefixed format (* + 40 hex chars = 41 chars)
    elif length == 41 and re.fullmatch(r"^\*[a-fA-F0-9]{40}$", cleaned):
        display_result = "Matches: MySQL 4.1+/5+ (Hashcat: 300)"
        candidates = [
            {
                "algorithm": "MySQL 4.1+/5+",
                "hashcat_mode": "300",
                "evidence": "structured_prefix_and_format",
                "explanation": "Standard MySQL user password format (* followed by 40 hex characters representing SHA1(SHA1(password))).",
            }
        ]

    is_ambiguous = len(candidates) > 1
    warning: Optional[str] = None
    if is_ambiguous:
        warning = (
            "Digest length and character format alone cannot definitively identify a hash algorithm. "
            "Multiple cryptographic algorithms produce identical output lengths."
        )
    elif not candidates:
        warning = "No supported algorithm matched the supplied length and character pattern."

    recommendation = (
        "Verify candidate algorithm using application context, database schema, prefix markers, "
        "or source code configuration."
        if candidates
        else "Check whether the hash was truncated, contains unexpected prefixes or encoding, or uses an unsupported format."
    )

    return {
        "input_summary": cleaned[:8] + "..." if len(cleaned) > 16 else cleaned,
        "input_length": length,
        "character_format": char_format,
        "candidates": candidates,
        "is_ambiguous": is_ambiguous,
        "warning": warning,
        "recommendation": recommendation,
        "result": display_result,
    }


def analyze_hashes(input_text: str) -> Dict[str, Any]:
    """Analyze input text which may contain one or multiple hash lines."""
    if not isinstance(input_text, str):
        raise TypeError("Input must be a string")

    stripped = input_text.strip()
    if not stripped:
        raise ValueError("Input cannot be empty")

    lines = [line.strip() for line in input_text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("Input cannot be empty")
    if len(lines) > MAX_HASH_LINES:
        raise ValueError(f"Hash identification accepts at most {MAX_HASH_LINES} non-empty lines")

    if len(lines) == 1:
        single = identify_single_hash(lines[0])
        return {
            "success": True,
            "input_length": single["input_length"],
            "character_format": single["character_format"],
            "candidates": single["candidates"],
            "is_ambiguous": single["is_ambiguous"],
            "warning": single["warning"],
            "recommendation": single["recommendation"],
            "result": single["result"],
            "lines": [single],
            "error": None,
        }

    # Multiple lines
    line_results = []
    summary_lines = []
    for idx, line in enumerate(lines, start=1):
        analysis = identify_single_hash(line)
        line_results.append(analysis)
        summary_lines.append(f"Line {idx} ({line[:8]}...): {analysis['result']}")

    combined_result = "\n".join(summary_lines)
    all_candidates = [cand for item in line_results for cand in item["candidates"]]
    any_ambiguous = any(item["is_ambiguous"] for item in line_results)

    return {
        "success": True,
        "input_length": len(stripped),
        "character_format": "multiline",
        "candidates": all_candidates,
        "is_ambiguous": any_ambiguous,
        "warning": "Multiple lines analyzed independently." + (
            " Some hashes have ambiguous candidate matches." if any_ambiguous else ""
        ),
        "recommendation": "Review each line's candidate analysis individually.",
        "result": combined_result,
        "lines": line_results,
        "error": None,
    }
