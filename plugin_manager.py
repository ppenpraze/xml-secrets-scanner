#!/usr/bin/env python3
"""
Plugin Manager for XML Secrets Scanner

Integrates all detect-secrets built-in plugins with our custom XML plugins.
Provides a unified interface for scanning with multiple plugins.
"""

from typing import List, Dict, Any, Generator, Optional
from detect_secrets.core.potential_secret import PotentialSecret

# Import detect-secrets built-in plugins
from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.azure_storage_key import AzureStorageKeyDetector
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from detect_secrets.plugins.cloudant import CloudantDetector
from detect_secrets.plugins.discord import DiscordBotTokenDetector
from detect_secrets.plugins.gitlab_token import GitLabTokenDetector
from detect_secrets.plugins.ibm_cloud_iam import IbmCloudIamDetector
from detect_secrets.plugins.ibm_cos_hmac import IbmCosHmacDetector
from detect_secrets.plugins.keyword import KeywordDetector
from detect_secrets.plugins.mailchimp import MailchimpDetector
from detect_secrets.plugins.npm import NpmDetector
from detect_secrets.plugins.openai import OpenAIDetector
from detect_secrets.plugins.private_key import PrivateKeyDetector
from detect_secrets.plugins.pypi_token import PypiTokenDetector
from detect_secrets.plugins.sendgrid import SendGridDetector
from detect_secrets.plugins.stripe import StripeDetector
from detect_secrets.plugins.telegram_token import TelegramBotTokenDetector

# Import our custom plugins
from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin


class PluginManager:
    """
    Manages all secret detection plugins.

    Provides a unified interface to scan with multiple plugins including:
    - Custom XML plugins (XMLPasswordPlugin, UnixCryptPlugin)
    - All detect-secrets built-in plugins (AWS, Stripe, Private Keys, etc.)
    """

    # Plugin registry with metadata
    AVAILABLE_PLUGINS = {
        # Custom plugins
        'xml_password': {
            'class': XMLPasswordPlugin,
            'description': 'Detect passwords in XML elements and attributes',
            'enabled_default': True,
        },
        'unix_crypt': {
            'class': UnixCryptPlugin,
            'description': 'Detect Unix crypt password hashes',
            'enabled_default': True,
        },

        # Detect-secrets built-in plugins
        'aws': {
            'class': AWSKeyDetector,
            'description': 'Detect AWS Access Keys',
            'enabled_default': True,
        },
        'azure_storage': {
            'class': AzureStorageKeyDetector,
            'description': 'Detect Azure Storage Keys',
            'enabled_default': True,
        },
        'basic_auth': {
            'class': BasicAuthDetector,
            'description': 'Detect Basic Auth credentials (user:pass@host)',
            'enabled_default': True,
        },
        'cloudant': {
            'class': CloudantDetector,
            'description': 'Detect Cloudant credentials',
            'enabled_default': True,
        },
        'discord': {
            'class': DiscordBotTokenDetector,
            'description': 'Detect Discord bot tokens',
            'enabled_default': True,
        },
        'gitlab': {
            'class': GitLabTokenDetector,
            'description': 'Detect GitLab tokens',
            'enabled_default': True,
        },
        'ibm_cloud_iam': {
            'class': IbmCloudIamDetector,
            'description': 'Detect IBM Cloud IAM keys',
            'enabled_default': True,
        },
        'ibm_cos_hmac': {
            'class': IbmCosHmacDetector,
            'description': 'Detect IBM COS HMAC credentials',
            'enabled_default': True,
        },
        'keyword': {
            'class': KeywordDetector,
            'description': 'Detect secrets via keywords (password=, api_key=, etc.)',
            'enabled_default': True,
        },
        'mailchimp': {
            'class': MailchimpDetector,
            'description': 'Detect Mailchimp API keys',
            'enabled_default': True,
        },
        'npm': {
            'class': NpmDetector,
            'description': 'Detect NPM tokens',
            'enabled_default': True,
        },
        'openai': {
            'class': OpenAIDetector,
            'description': 'Detect OpenAI API keys',
            'enabled_default': True,
        },
        'private_key': {
            'class': PrivateKeyDetector,
            'description': 'Detect RSA/SSH private keys',
            'enabled_default': True,
        },
        'pypi': {
            'class': PypiTokenDetector,
            'description': 'Detect PyPI tokens',
            'enabled_default': True,
        },
        'sendgrid': {
            'class': SendGridDetector,
            'description': 'Detect SendGrid API keys',
            'enabled_default': True,
        },
        'stripe': {
            'class': StripeDetector,
            'description': 'Detect Stripe API keys',
            'enabled_default': True,
        },
        'telegram': {
            'class': TelegramBotTokenDetector,
            'description': 'Detect Telegram bot tokens',
            'enabled_default': True,
        },
    }

    def __init__(self,
                 enabled_plugins: Optional[List[str]] = None,
                 disabled_plugins: Optional[List[str]] = None,
                 xml_password_config: Optional[Dict[str, Any]] = None,
                 unix_crypt_config: Optional[Dict[str, Any]] = None):
        """
        Initialize plugin manager.

        Args:
            enabled_plugins: List of plugin names to enable (None = all default)
            disabled_plugins: List of plugin names to disable
            xml_password_config: Configuration for XMLPasswordPlugin
            unix_crypt_config: Configuration for UnixCryptPlugin
        """
        self.plugins = []
        self.plugin_names = []
        self.xml_password_config = xml_password_config or {}
        self.unix_crypt_config = unix_crypt_config or {}

        self._load_plugins(enabled_plugins, disabled_plugins)

    def _load_plugins(self, enabled_plugins: Optional[List[str]], disabled_plugins: Optional[List[str]]):
        """Load and initialize plugins based on configuration."""
        disabled_plugins = disabled_plugins or []

        for plugin_name, plugin_info in self.AVAILABLE_PLUGINS.items():
            # Check if plugin should be loaded
            if enabled_plugins is not None:
                # Explicit whitelist mode
                if plugin_name not in enabled_plugins:
                    continue
            else:
                # Default mode with blacklist
                if plugin_name in disabled_plugins:
                    continue
                if not plugin_info['enabled_default']:
                    continue

            # Initialize plugin with appropriate config
            try:
                if plugin_name == 'xml_password':
                    plugin = plugin_info['class'](**self.xml_password_config)
                elif plugin_name == 'unix_crypt':
                    plugin = plugin_info['class'](**self.unix_crypt_config)
                else:
                    # Built-in plugins with no config
                    plugin = plugin_info['class']()

                self.plugins.append(plugin)
                self.plugin_names.append(plugin_name)

            except Exception as e:
                # Log error but continue loading other plugins
                print(f"Warning: Failed to load plugin {plugin_name}: {e}")

    def scan_line(self, filename: str, line: str, line_number: int = 0) -> Generator[PotentialSecret, None, None]:
        """
        Scan a line with all enabled plugins.

        Args:
            filename: File being scanned
            line: Line content
            line_number: Line number in file

        Yields:
            PotentialSecret objects from any plugin that detects a secret
        """
        for plugin in self.plugins:
            try:
                yield from plugin.analyze_line(filename, line, line_number)
            except Exception as e:
                # Don't let one plugin failure stop others
                print(f"Warning: Plugin {plugin.__class__.__name__} error on line {line_number}: {e}")

    def get_enabled_plugins(self) -> List[str]:
        """Get list of enabled plugin names."""
        return self.plugin_names.copy()

    def get_plugin_count(self) -> int:
        """Get number of enabled plugins."""
        return len(self.plugins)

    @classmethod
    def list_available_plugins(cls) -> List[Dict[str, Any]]:
        """
        Get list of all available plugins with metadata.

        Returns:
            List of dicts with plugin info (name, description, enabled_default)
        """
        return [
            {
                'name': name,
                'description': info['description'],
                'enabled_default': info['enabled_default'],
            }
            for name, info in cls.AVAILABLE_PLUGINS.items()
        ]

    @classmethod
    def create_default(cls, **kwargs):
        """Create plugin manager with default settings."""
        return cls(**kwargs)

    @classmethod
    def create_xml_only(cls, **xml_config):
        """Create plugin manager with only XML plugins enabled."""
        return cls(
            enabled_plugins=['xml_password', 'unix_crypt'],
            xml_password_config=xml_config
        )

    @classmethod
    def create_common_only(cls, **xml_config):
        """Create plugin manager with common plugins (XML, AWS, Private Keys, Keyword)."""
        return cls(
            enabled_plugins=['xml_password', 'unix_crypt', 'aws', 'private_key', 'keyword', 'basic_auth'],
            xml_password_config=xml_config
        )
