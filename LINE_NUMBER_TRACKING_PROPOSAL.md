# Line Number Tracking for Normalized XML - Design Proposals

## Problem Statement

When XML is normalized (multi-line elements converted to single-line), we lose the original line numbers where secrets appeared. This makes it difficult for users to locate secrets in the original file.

**Example:**
```xml
<!-- Original file (lines 5-7) -->
<database>
    <password>
        MySecretPassword123!
    </password>
</database>

<!-- After normalization (line 1) -->
<database><password>MySecretPassword123!</password></database>
```

When we detect the secret in the normalized version, we report "line 1", but the user needs to know it was originally on lines 5-7.

---

## Solution Approaches

### Approach 1: Line Mapping During Normalization (Recommended)

**Concept:** Build a mapping during normalization that tracks which original line each element started on.

#### Implementation Strategy

1. **During XML parsing:** Track source line numbers using a custom XML parser
2. **Create a line map:** Store element XPath → original line number
3. **During detection:** Look up original line number from the map
4. **Output:** Include both original and normalized line numbers

#### Pros:
- ✅ Accurate - preserves exact original line numbers
- ✅ Works for all secret types (element values, attributes, multi-line)
- ✅ Can report original line ranges (start-end)

#### Cons:
- ❌ More complex implementation
- ❌ Requires custom XML parsing or ElementTree extension
- ❌ Need to pass line map through the scanning process

---

### Approach 2: Pre-Scan Before Normalization (Simple)

**Concept:** Run detection TWICE - once on original, once on normalized.

#### Implementation Strategy

1. **First scan:** Line-based scan on original XML (captures line numbers)
2. **Second scan:** XML-parsed scan on normalized XML (captures multi-line secrets)
3. **Merge results:** Combine both, deduplicate
4. **Output:** Original scan has line numbers, normalized scan has element paths

#### Pros:
- ✅ Simple to implement
- ✅ No changes to normalization code
- ✅ Gets both line numbers AND element context

#### Cons:
- ❌ Scans files twice (slower)
- ❌ May have duplicate detections that need deduplication
- ❌ Line numbers only accurate for single-line secrets

---

### Approach 3: Search Original File After Detection (Fastest to Implement)

**Concept:** After detecting a secret in normalized XML, search for it in the original file.

#### Implementation Strategy

1. **Scan normalized XML:** Detect secrets with element paths
2. **For each secret found:** Search original file for the secret value
3. **Record line number:** Where the secret appears in original
4. **Output:** Include original line number

#### Pros:
- ✅ Very simple to implement
- ✅ Minimal code changes
- ✅ Works with existing normalization

#### Cons:
- ❌ Inaccurate if same secret appears multiple times
- ❌ Won't find secrets if normalized differently (whitespace changes)
- ❌ Requires regex/search for each secret

---

### Approach 4: XML Parser with Line Numbers (Most Accurate)

**Concept:** Use an XML parser that preserves source line information (like `lxml`).

#### Implementation Strategy

1. **Use lxml instead of ElementTree:** `lxml` provides `sourceline` attribute
2. **During parsing:** Extract line numbers from elements
3. **Store in mapping:** Element object → source line
4. **During detection:** Look up line from mapping
5. **Output:** Original line numbers

#### Code Example:
```python
from lxml import etree

# Parse with line numbers
parser = etree.XMLParser()
tree = etree.parse('file.xml', parser)
root = tree.getroot()

# Access line numbers
for element in root.iter():
    print(f"{element.tag} is on line {element.sourceline}")
```

#### Pros:
- ✅ Most accurate - parser tracks lines
- ✅ Works for all element types
- ✅ Industry standard approach
- ✅ Can get line ranges (start/end)

#### Cons:
- ❌ Requires `lxml` dependency (heavier than stdlib)
- ❌ Need to refactor to use lxml instead of ElementTree
- ❌ May have compatibility issues with malformed XML

---

### Approach 5: Hybrid - Annotate During Normalization (Best Balance)

**Concept:** Add line number comments during normalization, then extract them during scanning.

#### Implementation Strategy

1. **During normalization:** Add XML comments with original line info
   ```xml
   <!-- line:5-7 --><password>MySecretPassword123!</password>
   ```

2. **During scanning:** Parse comments to extract line numbers
3. **Match to secrets:** Associate secrets with nearby line annotations
4. **Output:** Original line numbers

#### Pros:
- ✅ No external dependencies
- ✅ Line info embedded in normalized XML
- ✅ Can inspect normalized XML manually and see line numbers
- ✅ Moderate complexity

#### Cons:
- ❌ Modifies normalized XML structure (adds comments)
- ❌ Need to handle comment parsing
- ❌ Slightly increases normalized file size

---

## Detailed Design: Approach 1 (Line Mapping)

**Recommended approach for accuracy and maintainability.**

### Step 1: Extend Normalization to Track Lines

```python
def normalize_xml_with_line_map(xml_content: str) -> Tuple[str, Dict[str, int]]:
    """
    Normalize XML and create a line mapping.

    Returns:
        (normalized_xml, line_map)

        line_map format:
        {
            "/root/database/password": 5,
            "/root/api/secret": 12,
            ...
        }
    """
    from lxml import etree

    # Parse with line tracking
    parser = etree.XMLParser()
    tree = etree.fromstring(xml_content.encode(), parser)

    # Build line map
    line_map = {}

    def build_map(element, path=""):
        current_path = f"{path}/{element.tag}"

        # Store original line number
        if hasattr(element, 'sourceline'):
            line_map[current_path] = element.sourceline

        # Handle attributes (they're on the same line as element)
        if hasattr(element, 'sourceline') and element.attrib:
            for attr_name in element.attrib:
                attr_path = f"{current_path}@{attr_name}"
                line_map[attr_path] = element.sourceline

        # Recurse
        for child in element:
            build_map(child, current_path)

    build_map(tree)

    # Normalize
    normalized = etree.tostring(tree, encoding='unicode')

    return normalized, line_map
```

### Step 2: Update Scanning to Use Line Map

```python
def scan_xml_file_with_lines(file_path: str, xml_plugin, unix_plugin):
    """Scan XML file and include original line numbers."""

    # Read original
    original_content = read_text_safely(file_path)

    # Normalize with line tracking
    normalized_xml, line_map = normalize_xml_with_line_map(original_content)

    # Parse normalized XML
    root = ET.fromstring(normalized_xml)

    # Scan
    results = []
    for element, path in walk_xml_tree(root):
        # Detect secrets in element
        secrets = detect_secrets(element)

        for secret in secrets:
            # Look up original line number
            original_line = line_map.get(path, 0)

            results.append({
                'file': file_path,
                'line_number': original_line,  # Original line!
                'element_path': path,
                'secret': secret.value,
                'type': secret.type
            })

    return results
```

### Step 3: Output Format

```json
{
  "file": "config.xml",
  "line_number": 5,
  "line_number_normalized": 1,
  "element_path": "/configuration/database/password",
  "parent_element": "database",
  "type": "XML Password",
  "secret": "MySecretPassword123!",
  "line_content": "<password>MySecretPassword123!</password>"
}
```

---

## Detailed Design: Approach 2 (Dual Scan)

**Simpler implementation with no new dependencies.**

### Step 1: Scan Original First (Line-Based)

```python
def scan_original_xml(file_path: str, plugins):
    """Line-based scan of original XML."""
    content = read_text_safely(file_path)

    results = []
    for line_num, line in enumerate(content.splitlines(), 1):
        secrets = detect_secrets_in_line(line, plugins)

        for secret in secrets:
            results.append({
                'file': file_path,
                'line_number': line_num,
                'secret': secret.value,
                'type': secret.type,
                'line_content': line.strip(),
                'detection_method': 'original_scan'
            })

    return results
```

### Step 2: Scan Normalized (Context-Aware)

```python
def scan_normalized_xml(file_path: str, plugins):
    """XML-parsed scan of normalized content."""
    content = read_text_safely(file_path)
    normalized = normalize_xml_content(content)

    root = ET.fromstring(normalized)

    results = []
    for element, path in walk_xml_tree(root):
        secrets = detect_secrets(element)

        for secret in secrets:
            results.append({
                'file': file_path,
                'element_path': path,
                'parent_element': element.tag,
                'secret': secret.value,
                'type': secret.type,
                'detection_method': 'normalized_scan'
            })

    return results
```

### Step 3: Merge Results

```python
def scan_with_dual_approach(file_path: str, plugins):
    """Scan both ways and merge results."""

    # Scan original (gets line numbers)
    original_results = scan_original_xml(file_path, plugins)

    # Scan normalized (gets element paths, multi-line secrets)
    normalized_results = scan_normalized_xml(file_path, plugins)

    # Merge and deduplicate
    merged = []
    seen_secrets = set()

    # Add original results first (they have line numbers)
    for result in original_results:
        secret_key = (result['file'], result['secret'], result['type'])
        if secret_key not in seen_secrets:
            merged.append(result)
            seen_secrets.add(secret_key)

    # Add normalized results if they're new
    for result in normalized_results:
        secret_key = (result['file'], result['secret'], result['type'])
        if secret_key not in seen_secrets:
            merged.append(result)
            seen_secrets.add(secret_key)

    return merged
```

---

## Detailed Design: Approach 3 (Post-Detection Search)

**Quickest to implement, least accurate.**

### Implementation

```python
def find_secret_in_original(file_path: str, secret_value: str) -> Optional[int]:
    """Search for secret in original file and return line number."""
    content = read_text_safely(file_path)

    for line_num, line in enumerate(content.splitlines(), 1):
        if secret_value in line:
            return line_num

    return None


def scan_with_line_lookup(file_path: str, plugins):
    """Scan normalized XML, then look up line numbers."""

    # Read original for later lookup
    original_content = read_text_safely(file_path)

    # Normalize and scan
    normalized = normalize_xml_content(original_content)
    root = ET.fromstring(normalized)

    results = []
    for element, path in walk_xml_tree(root):
        secrets = detect_secrets(element)

        for secret in secrets:
            # Look up line in original
            original_line = find_secret_in_original(file_path, secret.value)

            results.append({
                'file': file_path,
                'line_number': original_line or 0,
                'element_path': path,
                'secret': secret.value,
                'type': secret.type
            })

    return results
```

**Issue:** If the same secret appears multiple times, this will find the FIRST occurrence, which may not be correct.

---

## Comparison Matrix

| Approach | Accuracy | Complexity | Dependencies | Performance | Maintenance |
|----------|----------|------------|--------------|-------------|-------------|
| **1. Line Mapping (lxml)** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | lxml | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **2. Dual Scan** | ⭐⭐⭐⭐ | ⭐⭐ | None | ⭐⭐ (2x scan) | ⭐⭐⭐ |
| **3. Post-Search** | ⭐⭐ | ⭐ | None | ⭐⭐⭐ | ⭐⭐ |
| **4. lxml Only** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | lxml | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **5. Annotated XML** | ⭐⭐⭐⭐ | ⭐⭐⭐ | None | ⭐⭐⭐⭐ | ⭐⭐⭐ |

---

## Recommendation

### Short-term (Immediate): **Approach 2 - Dual Scan**

**Why:**
- ✅ No new dependencies
- ✅ Can implement today
- ✅ Gets both line numbers and element context
- ✅ Works with existing code

**Trade-off:** Scans files twice, but for most repos this is acceptable.

**Implementation Effort:** 2-3 hours

---

### Long-term (Best Solution): **Approach 1 - Line Mapping with lxml**

**Why:**
- ✅ Most accurate
- ✅ Industry standard approach
- ✅ Single scan (faster)
- ✅ Better for large repos
- ✅ Can get line ranges (start-end of multi-line elements)

**Trade-off:** Requires lxml dependency, but it's a standard library.

**Implementation Effort:** 1 day

---

## Proposed Output Format (All Approaches)

```json
{
  "file": "production.xml",
  "line_number": 42,
  "line_number_end": 44,
  "line_number_normalized": 15,
  "element_path": "/configuration/database/password",
  "parent_element": "database",
  "type": "XML Password",
  "secret": "MySecretPassword123!",
  "line_content": "<password>MySecretPassword123!</password>",
  "line_content_original": "    <password>\n        MySecretPassword123!\n    </password>",
  "detection_method": "element_value"
}
```

**Fields:**
- `line_number`: Original file line number (most important!)
- `line_number_end`: For multi-line elements, ending line
- `line_number_normalized`: Line in normalized XML (optional, for debugging)
- `element_path`: XPath to element
- `parent_element`: Immediate parent element
- `line_content`: Secret as detected (normalized)
- `line_content_original`: Original multi-line content (optional)

---

## Implementation Plan

### Phase 1: Dual Scan (This Week)

1. Implement `scan_original_xml()` - line-based scan
2. Implement `scan_normalized_xml()` - XML-parsed scan
3. Implement merge/deduplication logic
4. Update output format to include both line numbers and element paths
5. Add tests

### Phase 2: Line Mapping with lxml (Next Sprint)

1. Add lxml as optional dependency
2. Implement `normalize_xml_with_line_map()` using lxml
3. Update scanning to use line map
4. Add fallback to dual scan if lxml not available
5. Performance testing

### Phase 3: Enhanced Output (Future)

1. Add line ranges for multi-line elements
2. Include original multi-line content in output
3. Add visual context (lines before/after)
4. Generate HTML reports with line highlighting

---

## Example Usage

### With Dual Scan:
```bash
# Automatically scans both original and normalized
python3 scan_xml_with_context.py /repo --output results.json

# Output includes line numbers from original file
cat results.json | jq '.secrets[] | {file, line_number, element_path, secret}'
```

### With Line Mapping:
```bash
# Single scan with accurate line numbers
python3 scan_xml_with_context.py /repo --use-lxml --output results.json

# Can show line ranges for multi-line secrets
cat results.json | jq '.secrets[] | {file, line_start: .line_number, line_end: .line_number_end}'
```

---

## Testing Strategy

### Test Cases Needed:

1. **Single-line secret:** Should report correct line
2. **Multi-line secret:** Should report start line (and optionally end line)
3. **Duplicate secrets:** Should report all occurrences with different lines
4. **Attribute secrets:** Should report element's line
5. **Nested secrets:** Should report correct line even in deep nesting
6. **Malformed XML:** Should fall back gracefully

### Test File Example:
```xml
<!-- Line 1 -->
<?xml version="1.0"?>
<!-- Line 3 -->
<config>
    <!-- Line 5: Single-line secret -->
    <password>SingleLineSecret123!</password>

    <!-- Lines 8-10: Multi-line secret -->
    <api_key>
        MultiLineSecret456!
    </api_key>

    <!-- Line 13: Attribute secret -->
    <server hostname="localhost" password="AttributeSecret789!"/>

    <!-- Lines 16-21: Nested multi-line secret -->
    <database>
        <connection>
            <password>
                NestedMultiLineSecret!
            </password>
        </connection>
    </database>
</config>
```

**Expected output:**
```json
[
  {"line_number": 6, "secret": "SingleLineSecret123!"},
  {"line_number": 9, "line_number_end": 11, "secret": "MultiLineSecret456!"},
  {"line_number": 13, "secret": "AttributeSecret789!"},
  {"line_number": 18, "line_number_end": 20, "secret": "NestedMultiLineSecret!"}
]
```

---

## Questions for User

1. **Accuracy vs. Speed:** Do you prefer:
   - Dual scan (simple, slower) for immediate implementation?
   - lxml line mapping (accurate, faster) with 1-day implementation?

2. **Dependencies:** Are you comfortable adding `lxml` as a dependency?
   - If yes → Use Approach 1 or 4
   - If no → Use Approach 2 or 3

3. **Output Detail:** How much detail do you want?
   - Just original line number?
   - Line ranges (start-end)?
   - Original multi-line content?

4. **Backward Compatibility:** Should we maintain compatibility with current output format?
   - Add new fields but keep existing ones?
   - Or completely new format?

---

## My Recommendation

**Start with Approach 2 (Dual Scan) today**, then migrate to Approach 1 (lxml Line Mapping) when time permits.

**Rationale:**
- Gets you working line numbers immediately
- No new dependencies
- Can migrate incrementally
- Low risk

**Next Steps:**
1. I can implement Approach 2 now (2-3 hours)
2. Test with your sample files
3. Gather feedback
4. Plan migration to lxml if needed
