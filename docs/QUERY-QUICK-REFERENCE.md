# Cyberion Query Language - Quick Reference

## Basic Syntax

Every query starts with `events` and chains operators with pipes (`|`):

```
events | operator1 | operator2 | operator3...
```

---

## Operators

### WHERE - Filter Events

```
| where field == value
| where field != value
| where field > value
| where field < value
| where field >= value
| where field <= value
```

**String Matching:**
```
| where field contains "substring"
| where field startswith "prefix"
| where field endswith ".exe"
```

**NULL Checks:**
```
| where field == null
| where field != null
```

**Logical Combinations:**
```
| where field1 == "value" and field2 >= 3
| where field1 == "value" or field2 == "other"
| where not (field1 == "value")
```

### PROJECT - Select Columns

```
| project column1, column2, column3
| project column1 as alias1, column2
```

### SORT - Order Results

```
| sort by column1 asc
| sort by column1 desc
| sort by column1 desc, column2 asc
```

### TAKE - Limit Results

```
| take 100
| take 1000
```

### DISTINCT - Unique Rows

```
| distinct field1
| distinct field1, field2, field3
```

### SUMMARIZE - Aggregation

```
| summarize count()
| summarize count(field)
| summarize dcount(field)           # Distinct count
| summarize sum(field), avg(field)
| summarize count() by group_field
| summarize count(), max(severity) by hostname, user
```

---

## Available Fields

```
timestamp          received_at        source
agent_id           agent_name         hostname
os                 event_type         severity
success            pid                ppid
process_name       parent_process     user
filepath           command            message
ip_address
```

---

## Operators Reference

| Symbol | Meaning | Example |
|--------|---------|---------|
| `==` | Equals | `severity == 3` |
| `!=` | Not equals | `event_type != "auth"` |
| `>` | Greater | `pid > 1000` |
| `<` | Less | `severity < 5` |
| `>=` | Greater/equal | `severity >= 3` |
| `<=` | Less/equal | `timestamp <= "2026-08-10"` |
| `contains` | Has substring | `command contains "powershell"` |
| `startswith` | Starts with | `filepath startswith "C:\\"` |
| `endswith` | Ends with | `filepath endswith ".exe"` |
| `and` | Both true | `x == "y" and z >= 3` |
| `or` | Either true | `x == "y" or x == "z"` |
| `not` | Negation | `not (event_type == "auth")` |

---

## Time Functions

```
ago(5s)      # 5 seconds ago
ago(5m)      # 5 minutes ago
ago(1h)      # 1 hour ago
ago(24h)     # 1 day ago
ago(7d)      # 1 week ago
```

**Usage:**
```
| where timestamp > ago(1h)
| where timestamp >= ago(24h)
```

---

## Common Query Patterns

### Find Recent Events
```
events | take 100
events | sort by timestamp desc | take 50
```

### Filter by Type & Severity
```
events | where event_type == "process" and severity >= 3
```

### Process Execution Analysis
```
events
| where event_type == "process"
| where process_name == "powershell.exe"
| project timestamp, hostname, user, command
| sort by timestamp desc
| take 100
```

### Authentication Failures
```
events
| where event_type == "authentication"
| where success == false
| summarize count() by user
| sort by count desc
```

### Host Summary
```
events
| where severity >= 3
| summarize count(), dcount(user) by hostname
| sort by count desc
```

### Recent Suspicious Activity
```
events
| where timestamp > ago(24h)
| where severity >= 3
| sort by timestamp desc
| take 50
```

### Distinct Processes
```
events
| where event_type == "process"
| distinct process_name
```

### File Access Summary
```
events
| where event_type == "file"
| where filepath endswith ".exe"
| summarize count() by filepath
| sort by count desc
```

---

## Tips & Best Practices

### ✅ DO

- **Use indexed fields for speed:** `severity`, `event_type`, `hostname`, `timestamp`
- **Filter early:** Put `where` early in pipeline
- **Limit results:** Always use `take` to avoid loading huge result sets
- **Use specific comparisons:** `==` is faster than `contains`
- **Quote string values:** `"powershell.exe"` not `powershell.exe`

### ❌ DON'T

- **Don't fetch all rows:** `events | project * | where message contains "x"` (slow)
- **Don't use `contains` for exact matches:** Use `==` instead
- **Don't request millions of results:** Limit is 10,000 rows
- **Don't forget pipes:** Each operator needs `|` prefix
- **Don't type operators wrong:** `wher` → `where`, `proces` → `process_name`

---

## Error Messages

### "Unknown field 'proces_name'"
**Fix:** Typo in field name. Use `process_name`.

### "Parse error: Unexpected token"
**Fix:** Check pipe placement: `events | where ...` (not `events where ...`)

### "Validation error: Unknown aggregation function"
**Fix:** Use valid functions: `count`, `dcount`, `sum`, `avg`, `min`, `max`

### "Query returned X events in Y ms"
**Success!** This shows execution time and result count.

---

## Examples by Use Case

### Threat Hunting: PowerShell Execution
```
events
| where event_type == "process"
| where process_name == "powershell.exe"
| where command contains "DownloadString" or command contains "IEX"
| project timestamp, hostname, user, command
| sort by timestamp desc
| take 100
```

### Incident Investigation: Failed Logins
```
events
| where event_type == "authentication"
| where success == false
| where user == "admin"
| sort by timestamp desc
| take 50
```

### Anomaly Detection: High Severity Events
```
events
| where severity >= 4
| where timestamp > ago(24h)
| summarize count() by event_type, hostname
| sort by count desc
```

### Compliance Audit: File Access
```
events
| where event_type == "file"
| where filepath contains "sensitive"
| where timestamp > ago(7d)
| project timestamp, user, filepath, command
| sort by timestamp asc
```

### Performance Analysis: Top Processes
```
events
| where event_type == "process"
| summarize count() as executions, dcount(user) as unique_users by process_name
| sort by executions desc
| take 20
```

---

## Keyboard Shortcuts

| Action | Key |
|--------|-----|
| Run Query | Enter (in query field) or click "Run Query" |
| Clear Query | Click "Clear" button |
| Previous Query | (Not yet implemented - feature for future) |

---

## Limits

- **Max results:** 10,000 rows per query
- **Query complexity:** No hard limit (nested parentheses OK)
- **String length:** No limit (SQLite dependent)
- **Execution timeout:** ~30 seconds (database dependent)

---

## See Also

- [Full User Guide](docs/query-language.md)
- [Architecture Details](docs/QUERY-ARCHITECTURE.md)
- [Test Examples](tests/test_query_language.py)

---

## Questions?

Refer to the full documentation in `docs/query-language.md` or check the test examples in `tests/test_query_language.py` for additional patterns.
