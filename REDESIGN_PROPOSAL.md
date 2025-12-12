# Redesign Proposal: Properly Leverage Detect-Secrets

## Current Issues

1. **Reinventing the wheel**: We're only using our custom plugins, not leveraging detect-secrets' built-in plugins
2. **Missing detections**: Not using AWS, API keys, Private Keys, Basic Auth, etc. detectors
3. **Limited scope**: Only detecting XML passwords and Unix crypt hashes

## Available Detect-Secrets Plugins

```python
# Built-in plugins available:
- AWSKeyDetector          # AWS Access Keys
- AzureStorageKeyDetector # Azure Storage Keys
- BasicAuthDetector       # Basic Auth (user:pass@host)
- CloudantDetector        # Cloudant credentials
- DiscordBotTokenDetector # Discord tokens
- GitLabTokenDetector     # GitLab tokens
- IBMCloudIamDetector     # IBM Cloud IAM
- IBMCosHmacDetector      # IBM COS HMAC
- KeywordDetector         # Generic keyword-based (password=, api_key=, etc.)
- MailchimpDetector       # Mailchimp API keys
- NPMDetector             # NPM tokens
- OpenAIDetector          # OpenAI API keys
- PrivateKeyDetector      # RSA/SSH private keys
- PyPiTokenDetector       # PyPI tokens
- SendGridDetector        # SendGrid API keys
- SlackDetector           # Slack tokens
- SoftlayerDetector       # Softlayer credentials
- StripeDetector          # Stripe API keys
- TelegramBotTokenDetector # Telegram tokens
```

## Proposed Architecture

### Scanner with All Plugins

```python
# scan_with_all_plugins.py

from detect_secrets.plugins.aws import AWSKeyDetector
from detect_secrets.plugins.private_key import PrivateKeyDetector
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from detect_secrets.plugins.keyword import KeywordDetector
from detect_secrets.plugins.stripe import StripeDetector
# ... import all plugins

from xml_plugins import XMLPasswordPlugin, UnixCryptPlugin

def create_plugin_suite():
    """Create comprehensive plugin suite."""
    return [
        # Our custom XML plugins
        XMLPasswordPlugin(),
        UnixCryptPlugin(),

        # Built-in detect-secrets plugins
        AWSKeyDetector(),
        PrivateKeyDetector(),
        BasicAuthDetector(),
        KeywordDetector(),
        StripeDetector(),
        # ... add more
    ]

def scan_with_all_plugins(file_path, plugins):
    """Scan file with all plugins."""
    results = []

    content = read_file(file_path)
    for line_num, line in enumerate(content.splitlines(), 1):
        for plugin in plugins:
            for secret in plugin.analyze_line(file_path, line, line_num):
                results.append({
                    'file': file_path,
                    'line_number': line_num,
                    'type': secret.type,
                    'secret': secret.secret_value,
                    'plugin': plugin.__class__.__name__
                })

    return results
```

## Benefits

1. **Comprehensive detection**: Detect AWS keys, API tokens, private keys, etc.
2. **No reinvention**: Use battle-tested plugins from detect-secrets
3. **Extensible**: Easy to add new plugins
4. **Configurable**: Users can enable/disable specific plugins

## Implementation Plan

### Phase 1: Add Plugin Suite Manager

Create `plugin_manager.py`:

```python
class PluginManager:
    def __init__(self, config=None):
        self.plugins = []
        self.config = config or {}
        self._load_plugins()

    def _load_plugins(self):
        """Load all enabled plugins."""
        # Custom plugins
        if self.config.get('xml_password', True):
            self.plugins.append(XMLPasswordPlugin(...))

        if self.config.get('unix_crypt', True):
            self.plugins.append(UnixCryptPlugin(...))

        # Built-in plugins
        if self.config.get('aws', True):
            self.plugins.append(AWSKeyDetector())

        if self.config.get('private_key', True):
            self.plugins.append(PrivateKeyDetector())

        # ... add all plugins

    def scan_line(self, filename, line, line_number):
        """Scan line with all enabled plugins."""
        for plugin in self.plugins:
            yield from plugin.analyze_line(filename, line, line_number)
```

### Phase 2: Update Scanners

Update `scan_with_plugins.py` and `scan_xml_with_context.py`:

```python
def scan_file(file_path, plugin_manager):
    """Scan file with plugin manager."""
    results = []
    content = read_file(file_path)

    for line_num, line in enumerate(content.splitlines(), 1):
        for secret in plugin_manager.scan_line(file_path, line, line_num):
            results.append({
                'file': file_path,
                'line_number': line_num,
                'type': secret.type,
                'secret': secret.secret_value,
                # Additional metadata
            })

    return results
```

### Phase 3: CLI Configuration

Add CLI options to enable/disable plugins:

```bash
# Enable all plugins (default)
python3 scan_with_plugins.py /repo --output results.json

# Disable specific plugins
python3 scan_with_plugins.py /repo --disable-aws --disable-private-key

# Enable only specific plugins
python3 scan_with_plugins.py /repo --only xml_password,unix_crypt,aws

# Show available plugins
python3 scan_with_plugins.py --list-plugins
```

### Phase 4: Configuration File

Support `.secrets.yaml` config:

```yaml
# .secrets.yaml
plugins:
  xml_password:
    enabled: true
    include_entities: ['prod_.*', 'live_.*']
    exclude_entities: ['test_.*', 'dev_.*']
    min_password_length: 6

  unix_crypt:
    enabled: true
    detect_des: false

  aws:
    enabled: true

  private_key:
    enabled: true

  keyword:
    enabled: true
    keywords:
      - password
      - api_key
      - secret
      - token
```

## Example Output

With all plugins enabled:

```json
{
  "total_secrets_found": 15,
  "secrets": [
    {
      "file": "config.xml",
      "line_number": 5,
      "type": "XML Password",
      "secret": "MyPassword123!",
      "plugin": "XMLPasswordPlugin"
    },
    {
      "file": "credentials.txt",
      "line_number": 10,
      "type": "AWS Access Key",
      "secret": "AKIAIOSFODNN7EXAMPLE",
      "plugin": "AWSKeyDetector"
    },
    {
      "file": "api_config.yaml",
      "line_number": 15,
      "type": "Stripe API Key",
      "secret": "sk_live_...",
      "plugin": "StripeDetector"
    },
    {
      "file": "deploy_key",
      "line_number": 1,
      "type": "Private Key",
      "secret": "-----BEGIN RSA PRIVATE KEY-----",
      "plugin": "PrivateKeyDetector"
    }
  ]
}
```

## Migration Strategy

### Backward Compatibility

1. Keep existing CLI options working
2. Add new options incrementally
3. Default to all plugins enabled

### Testing

1. Test each plugin individually
2. Test plugin combinations
3. Ensure no performance regression
4. Validate output format

## Questions to Answer

1. **Which plugins should be enabled by default?**
   - All plugins? (comprehensive)
   - Only XML + common plugins? (focused)

2. **How to handle plugin conflicts?**
   - If multiple plugins detect same secret?
   - Deduplicate or show all?

3. **Performance considerations?**
   - All plugins on every line = slower
   - Option to skip certain file types per plugin?

4. **Configuration complexity?**
   - Simple CLI flags?
   - Config file?
   - Both?

## Recommendation

**Phase 1 (Immediate)**: Add KeywordDetector, AWSKeyDetector, PrivateKeyDetector
**Phase 2 (Next week)**: Add all remaining plugins with config file support
**Phase 3 (Future)**: Advanced filtering and plugin customization

This gives users immediate value while maintaining backward compatibility.
