# STRYKER Plugin System

Drop any Python file here and STRYKER auto-discovers it.

## Plugin template

```python
PLUGIN = {
    "id":          "my_tool",
    "name":        "My Tool",
    "description": "What this tool does",
    "checks":      "What it checks",
    "author":      "Your Name",
    "version":     "1.0.0",
}

def run(target, output_file=None, **kwargs):
    findings = []
    findings.append({
        "severity":       "HIGH",
        "title":          "Finding title",
        "detail":         "What was found",
        "recommendation": "How to fix it",
    })
    return findings
```
