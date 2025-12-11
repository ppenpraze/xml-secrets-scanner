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

            # Check against default element patterns or custom patterns
            should_check = False

            # Check include/exclude entity patterns
            if not self._should_include_entity(element_name):
                continue

            # Check if element name matches default secret patterns
            if element_name.lower() in self.default_element_patterns:
                should_check = True

            # Check custom include patterns
            if self.include_entity_patterns:
                for pattern in self.include_entity_patterns:
                    if pattern.search(element_name):
                        should_check = True
                        break

            if not should_check:
                continue

            # Validate the value
            if not self._is_valid_secret(element_value):
                continue

            yield PotentialSecret(
                type=self.secret_type,
                filename=filename,
                secret=element_value,
                line_number=line_number,
            )

    def _is_valid_secret(self, value: str) -> bool:
        """Check if a value is a valid secret."""
        if not value:
            return self.detect_empty

        # Check minimum length
        if len(value) < self.min_password_length:
            return False

        # Check if it's a placeholder
        if self._is_placeholder(value):
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
        detect_des: bool = True,
        detect_md5: bool = True,
        detect_bcrypt: bool = True,
        detect_sha256: bool = True,
        detect_sha512: bool = True,
        detect_yescrypt: bool = True,
        **kwargs
    ):
        self.detect_des = detect_des
        self.detect_md5 = detect_md5
        self.detect_bcrypt = detect_bcrypt
        self.detect_sha256 = detect_sha256
        self.detect_sha512 = detect_sha512
        self.detect_yescrypt = detect_yescrypt

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
            # yescrypt: $y$ or $7$
            patterns.append(
                re.compile(r'\$[y7]\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+')
            )

        if self.detect_des:
            # Traditional DES: 13 characters from [a-zA-Z0-9./]
            # Be more strict to avoid false positives - look for word boundaries
            patterns.append(
                re.compile(r'(?:^|["\'\s>:=])[a-zA-Z0-9./]{13}(?:["\'\s<:,]|$)')
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
                    # DES hashes should have some variety in characters
                    if len(set(secret)) < 8:  # At least 8 unique characters
                        continue

                yield PotentialSecret(
                    type=self.secret_type,
                    filename=filename,
                    secret=secret,
                    line_number=line_number,
                )
