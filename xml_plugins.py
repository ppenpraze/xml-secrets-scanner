"""
Custom detect-secrets plugins for XML password and Unix crypt detection.

These plugins extend detect-secrets with XML-aware secret detection and
support for flexible include/exclude patterns for XML entities and nodes.
"""

import re
from typing import Generator, Set, Optional, List
from detect_secrets.plugins.base import RegexBasedDetector
from detect_secrets.core.potential_secret import PotentialSecret


class XMLPasswordPlugin(RegexBasedDetector):
    """
    Detects passwords and secrets in XML attributes and elements.

    Supports flexible configuration for including/excluding specific XML
    entities, attributes, and node names.

    Configuration options:
    - include_entities: List of regex patterns for XML entities to INCLUDE
    - exclude_entities: List of regex patterns for XML entities to EXCLUDE
    - include_attributes: List of regex patterns for XML attributes to INCLUDE
    - exclude_attributes: List of regex patterns for XML attributes to EXCLUDE
    - min_password_length: Minimum length for detected passwords (default: 4)
    - detect_empty: Whether to detect empty passwords (default: False)
    """

    secret_type = 'XML Password'

    def __init__(
        self,
        include_entities: Optional[List[str]] = None,
        exclude_entities: Optional[List[str]] = None,
        include_attributes: Optional[List[str]] = None,
        exclude_attributes: Optional[List[str]] = None,
        min_password_length: int = 4,
        detect_empty: bool = False,
        **kwargs
    ):
        super().__init__(**kwargs)

        self.min_password_length = min_password_length
        self.detect_empty = detect_empty

        # Compile include/exclude patterns
        self.include_entity_patterns = self._compile_patterns(include_entities or [])
        self.exclude_entity_patterns = self._compile_patterns(exclude_entities or [])
        self.include_attribute_patterns = self._compile_patterns(include_attributes or [])
        self.exclude_attribute_patterns = self._compile_patterns(exclude_attributes or [])

        # Default patterns for common password-like attributes
        self.default_attribute_patterns = [
            'password', 'passwd', 'pwd', 'pass',
            'secret', 'api_key', 'apikey', 'api-key',
            'auth_token', 'authtoken', 'auth-token',
            'access_token', 'accesstoken', 'access-token',
            'private_key', 'privatekey', 'private-key',
            'client_secret', 'clientsecret', 'client-secret',
            # encryption / AES related
            'aes_key', 'aeskey', 'aes-key',
            'encryption_key', 'encryptionkey', 'encryption-key',
            'crypto_key', 'cryptokey', 'crypto-key',
            'cipher_key', 'cipherkey', 'cipher-key',
            'keystore_password', 'keystore_pass', 'keystorepass',
        ]

        # Default patterns for common secret-like elements
        self.default_element_patterns = [
            'password', 'passwd', 'pwd', 'pass',
            'secret', 'apiKey', 'api_key', 'api-key',
            'authToken', 'auth_token', 'auth-token',
            'accessToken', 'access_token', 'access-token',
            'privateKey', 'private_key', 'private-key',
            'clientSecret', 'client_secret', 'client-secret',
            'connectionString', 'connection_string', 'connection-string',
            # encryption / AES related
            'aesKey', 'aes_key', 'encryptionKey', 'encryption_key',
            'cryptoKey', 'crypto_key', 'cipherKey', 'cipher_key',
            'keystorePassword', 'keystore_password',
        ]

        # Placeholder values to ignore
        self.placeholder_values = {
            'password', 'changeme', 'example', 'test', 'sample',
            'placeholder', 'xxx', '****', 'your_password_here',
            'enter_password', 'your_password', 'insert_password',
            'admin', '123456', 'qwerty', 'letmein',
        }

    @property
    def denylist(self) -> List[re.Pattern]:
        """
        Return list of regex patterns for XML passwords.
        This is required by RegexBasedDetector but we use analyze_line for actual detection.
        """
        # Return empty list since we override analyze_line
        return []

    def _compile_patterns(self, patterns: List[str]) -> List[re.Pattern]:
        """Compile regex patterns from strings."""
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                # Skip invalid patterns
                pass
        return compiled

    def _should_include_entity(self, entity_name: str) -> bool:
        """Check if an entity should be included based on include/exclude patterns."""
        # If exclude patterns exist and match, exclude
        if self.exclude_entity_patterns:
            for pattern in self.exclude_entity_patterns:
                if pattern.search(entity_name):
                    return False

        # If include patterns exist, only include if matched
        if self.include_entity_patterns:
            for pattern in self.include_entity_patterns:
                if pattern.search(entity_name):
                    return True
            return False

        return True

    def _should_include_attribute(self, attribute_name: str) -> bool:
        """Check if an attribute should be included based on include/exclude patterns."""
        # If exclude patterns exist and match, exclude
        if self.exclude_attribute_patterns:
            for pattern in self.exclude_attribute_patterns:
                if pattern.search(attribute_name):
                    return False

        # If include patterns exist, only include if matched
        if self.include_attribute_patterns:
            for pattern in self.include_attribute_patterns:
                if pattern.search(attribute_name):
                    return True
            # If no include patterns match, check default patterns
            return attribute_name.lower() in self.default_attribute_patterns

        # No include patterns, check default patterns
        return attribute_name.lower() in self.default_attribute_patterns

    def _is_placeholder(self, value: str) -> bool:
        """Check if a value looks like a placeholder."""
        if not value:
            return True

        value_lower = value.lower().strip()

        # Check against known placeholders
        if value_lower in self.placeholder_values:
            return True

        # Check for template-like values
        if value.startswith('${') or value.startswith('{{') or value.startswith('%'):
            return True

        # Check for environment variable references
        if value.startswith('$') and len(value) > 1:
            return True

        # Check for EXAMPLE_ prefix or suffix (common in test data)
        value_upper = value.upper()
        if value_upper.startswith('EXAMPLE_') or value_upper.endswith('_EXAMPLE') or 'EXAMPLE' in value_upper:
            return True

        return False

    def _calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not value or len(value) < 2:
            return 0.0

        from collections import Counter
        import math

        # Count character frequencies
        counts = Counter(value)
        total = len(value)

        # Calculate Shannon entropy
        entropy = -sum((count/total) * math.log2(count/total) for count in counts.values())

        return entropy

    def _is_high_entropy(self, value: str, threshold: float = 3.5) -> bool:
        """Check if a value has high entropy (likely a password/secret)."""
        if len(value) < 8:
            return False

        entropy = self._calculate_entropy(value)

        # Adjust threshold based on length
        # Longer strings naturally have higher entropy
        if len(value) >= 20:
            adjusted_threshold = threshold + 0.5
        else:
            adjusted_threshold = threshold

        return entropy >= adjusted_threshold

    def _element_name_contains_pattern(self, element_name: str) -> bool:
        """Check if element name contains any default secret pattern (substring match)."""
        elem_lower = element_name.lower()

        # Check if any pattern is a substring of the element name
        for pattern in self.default_element_patterns:
            if pattern.lower() in elem_lower:
                return True

        return False

    def _attribute_name_contains_pattern(self, attribute_name: str) -> bool:
        """Check if attribute name contains any default secret pattern (substring match)."""
        attr_lower = attribute_name.lower()

        # Check if any pattern is a substring of the attribute name
        for pattern in self.default_attribute_patterns:
            if pattern.lower() in attr_lower:
                return True

        return False

    def _matches_any_pattern(self, name: str, patterns: List[re.Pattern]) -> bool:
        """Check if name matches any of the provided regex patterns."""
        if not patterns:
            return False

        for pattern in patterns:
            if pattern.search(name):
                return True

        return False

    def _looks_like_base64(self, s: str) -> bool:
        return bool(re.fullmatch(r'[A-Za-z0-9+/=]+', s)) and len(s) % 4 == 0

    def _looks_like_hex(self, s: str) -> bool:
        return bool(re.fullmatch(r'[0-9A-Fa-f]+', s))

    def _looks_like_aes_key(self, value: str) -> bool:
        """Heuristic: AES keys are commonly 128/192/256-bit.
        - Hex lengths: 32, 48, 64
        - Base64 lengths (unpadded typical): 24, 32, 44 (may include '=')
        """
        v = value.strip().replace(' ', '')
        # Hex
        if self._looks_like_hex(v) and len(v) in (32, 48, 64):
            return True
        # Base64 (ignore minor punctuation at ends)
        if self._looks_like_base64(v) and len(v) in (24, 32, 44):
            return True
        return False

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        **kwargs
    ) -> Generator[PotentialSecret, None, None]:
        """
        Analyze a line for XML passwords.

        Yields PotentialSecret objects for any detected secrets.
        """
        # Pattern 1: XML attributes (e.g., password="secret")
        attr_pattern = re.compile(
            r'(\w+)\s*=\s*["\']([^"\']*)["\']',
            re.IGNORECASE
        )

        for match in attr_pattern.finditer(line):
            attr_name = match.group(1)
            attr_value = match.group(2)

            # Check if we should process this attribute
            if not self._should_include_attribute(attr_name):
                continue

            # Validate the value
            if not self._is_valid_secret(attr_value):
                continue

            yield PotentialSecret(
                type=self.secret_type,
                filename=filename,
                secret=attr_value,
                line_number=line_number,
            )

        # Pattern 2: XML elements (e.g., <password>secret</password>)
        element_pattern = re.compile(
            r'<(\w+)>([^<]+)</\1>',
            re.IGNORECASE
        )

        for match in element_pattern.finditer(line):
            element_name = match.group(1)
            element_value = match.group(2).strip()

            # STEP 1: Determine if this is potentially a secret-like element
            # Check if element name contains any default patterns (substring match)
            matches_default = self._element_name_contains_pattern(element_name)

            # Check if element matches custom include patterns (regex match)
            matches_include = self._matches_any_pattern(element_name, self.include_entity_patterns)

            # If neither default nor include patterns match, skip
            if not matches_default and not matches_include:
                continue

            # STEP 2: Check if explicitly excluded
            if self._matches_any_pattern(element_name, self.exclude_entity_patterns):
                continue

            # STEP 3: Validate the value
            # For password-like fields, use high-entropy detection
            is_password_field = matches_default or matches_include
            if not self._is_valid_secret(element_value, is_password_field):
                continue

            yield PotentialSecret(
                type=self.secret_type,
                filename=filename,
                secret=element_value,
                line_number=line_number,
            )

        # Pattern 3: key[:=]value style in non-XML files (properties, conf, yaml-ish)
        # Examples: password=foo, encryption_key: "...", aes_key: AbCd==
        kv_pattern = re.compile(r'(\b[\w\.-]+)\s*[:=]\s*(["\"])?.*?\2')
        # A more controlled capture to get the value without trailing comments
        kv_iter = re.finditer(r'(\b[\w\.-]+)\s*[:=]\s*(["\"])?(.*?)\2(?:\s*[#;].*)?$', line)
        for m in kv_iter:
            key = m.group(1)
            val = (m.group(3) or '').strip()
            if not val:
                continue

            # Decide if key should be considered (reuse attribute logic)
            if not self._should_include_attribute(key):
                # If not in default list, also allow AES/encryption named keys heuristically
                lowered = key.lower()
                aes_like = any(x in lowered for x in (
                    'aes', 'encrypt', 'crypto', 'cipher', 'keystore'
                ))
                if not aes_like:
                    continue

            # Validate value
            if not self._is_valid_secret(val):
                # Special-case AES/encryption keys: allow shorter values if they look like AES material
                if not self._looks_like_aes_key(val):
                    continue

            yield PotentialSecret(
                type=self.secret_type,
                filename=filename,
                secret=val,
                line_number=line_number,
            )

    def _is_valid_secret(self, value: str, is_password_field: bool = False) -> bool:
        """Check if a value is a valid secret.

        Args:
            value: The value to validate
            is_password_field: True if this is a password/secret field (enables entropy check)
        """
        if not value:
            return self.detect_empty

        # Check if it's a placeholder first (before length check)
        if self._is_placeholder(value):
            return False

        # For password fields with reasonable length, check entropy
        if is_password_field and len(value) >= 8:
            # High entropy values are likely real secrets
            if self._is_high_entropy(value):
                return True
            # For password fields, also accept longer values even without high entropy
            # (e.g., passphrases like "correct horse battery staple")
            if len(value) >= 12:
                return True

        # Check minimum length
        if len(value) < self.min_password_length:
            return False

        return True


class UnixCryptPlugin(RegexBasedDetector):
    """
    Detects Unix crypt format password hashes.

    Supports detection of various Unix crypt formats:
    - Traditional DES (13 characters)
    - MD5: $1$salt$hash
    - Blowfish/bcrypt: $2a$, $2b$, $2x$, $2y$
    - SHA-256: $5$salt$hash
    - SHA-512: $6$salt$hash
    - yescrypt: $y$, $7$

    Configuration options:
    - detect_des: Detect traditional DES hashes (default: True)
    - detect_md5: Detect MD5 hashes (default: True)
    - detect_bcrypt: Detect bcrypt hashes (default: True)
    - detect_sha256: Detect SHA-256 hashes (default: True)
    - detect_sha512: Detect SHA-512 hashes (default: True)
    - detect_yescrypt: Detect yescrypt hashes (default: True)
    """

    secret_type = 'Unix Crypt Hash'

    def __init__(
        self,
        detect_des: bool = False,  # Disabled by default due to high false positive rate
        detect_md5: bool = True,
        detect_bcrypt: bool = True,
        detect_sha256: bool = True,
        detect_sha512: bool = True,
        detect_yescrypt: bool = True,
        require_des_context: bool = True,  # If DES enabled, require context words
        **kwargs
    ):
        self.detect_des = detect_des
        self.detect_md5 = detect_md5
        self.detect_bcrypt = detect_bcrypt
        self.detect_sha256 = detect_sha256
        self.detect_sha512 = detect_sha512
        self.detect_yescrypt = detect_yescrypt
        self.require_des_context = require_des_context

        super().__init__(**kwargs)

    @property
    def denylist(self) -> List[re.Pattern]:
        """
        Return list of regex patterns for Unix crypt hashes.

        This property is used by RegexBasedDetector to define what to detect.
        """
        patterns = []

        if self.detect_md5:
            # MD5: $1$salt$hash (salt: up to 8 chars, hash: 22 chars)
            patterns.append(
                re.compile(r'\$1\$[a-zA-Z0-9./]{1,8}\$[a-zA-Z0-9./]{22}')
            )

        if self.detect_bcrypt:
            # Blowfish/bcrypt: $2a$, $2b$, $2x$, $2y$ (cost: 2 digits, salt+hash: 53 chars)
            patterns.append(
                re.compile(r'\$2[abxy]\$\d{2}\$[a-zA-Z0-9./]{53}')
            )

        if self.detect_sha256:
            # SHA-256: $5$[rounds=N$]salt$hash (salt: up to 16 chars, hash: 43 chars)
            patterns.append(
                re.compile(r'\$5\$(?:rounds=\d+\$)?[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{43}')
            )

        if self.detect_sha512:
            # SHA-512: $6$[rounds=N$]salt$hash (salt: up to 16 chars, hash: 86 chars)
            patterns.append(
                re.compile(r'\$6\$(?:rounds=\d+\$)?[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]{86}')
            )

        if self.detect_yescrypt:
            # yescrypt: $y$ or legacy $7$ with multiple segments. To reduce FPs,
            # enforce that the final segment (encoded hash) is reasonably long.
            # Example: $y$...$<hash>
            patterns.append(
                re.compile(r'\$(?:y|7)\$[^\s$]+\$[a-zA-Z0-9./]{32,}')
            )

        if self.detect_des:
            # Traditional DES: exactly 13 chars from [a-zA-Z0-9./], with strict
            # token boundaries (not part of a longer string). Use lookarounds.
            patterns.append(
                re.compile(r'(?<![A-Za-z0-9./])[A-Za-z0-9./]{13}(?![A-Za-z0-9./])')
            )

        return patterns

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        **kwargs
    ) -> Generator[PotentialSecret, None, None]:
        """
        Analyze a line for Unix crypt hashes.

        Yields PotentialSecret objects for any detected hashes.
        """
        for pattern in self.denylist:
            for match in pattern.finditer(line):
                secret = match.group(0).strip()

                # Clean up any surrounding quotes or characters
                secret = secret.strip('"\'<>:=, ')

                # Additional validation for DES hashes to reduce false positives
                if len(secret) == 13 and self.detect_des:
                    # Require context words if configured
                    if self.require_des_context:
                        if not re.search(r'(?i)\b(crypt|hash|passwd|password|shadow)\b', line):
                            continue
                    # DES hashes should have some variety in characters
                    if len(set(secret)) < 8:  # At least 8 unique characters
                        continue

                yield PotentialSecret(
                    type=self.secret_type,
                    filename=filename,
                    secret=secret,
                    line_number=line_number,
                )
