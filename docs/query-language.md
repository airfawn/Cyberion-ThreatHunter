# Cyberion Query Language

## Overview

The **Cyberion Query Language (CQL)** is a KQL-inspired query language designed for searching, filtering, transforming, and aggregating security events in the Cyberion ThreatShield database.

Unlike raw SQL, CQL is:
- **Safe**: No SQL injection possible; all queries use parameterized statements
- **Intuitive**: Familiar pipeline syntax with clear operator semantics
- **Validated**: Field names and operators are validated before execution
- **Extensible**: Future operators can be added without breaking existing queries

## Query Structure

All queries follow this pattern:

```
events
| operator1
| operator2
| operator3
...
```

Every query starts with `events` (the data source) and then applies zero or more pipeline operators separated by pipes (`|`).

### Example Queries

**Find severe authentication failures:**
```
events
| where event_type == "authentication" and success == false and severity >= 3
| sort by timestamp desc
| take 100
```

**Count process executions by hostname:**
```
events
| where event_type == "process"
| summarize count() by hostname
| sort by count desc
```

**Distinct users with command-line activity:**
```
events
| where event_type == "process" and command contains "-c"
| distinct user
```

---

## Available Fields

The following fields can be queried:

### Identity & Source
- `id` - Event ID (unique per event)
- `source` - Event source (e.g., "log:sysmon", "log:audit")
- `agent_id` - Agent ID that collected the event
- `agent_name` - Human-readable agent name

### Timestamp & Timing
- `timestamp` - Event time (agent-provided)
- `received_at` - Time event was received by Cyberion

### System Information
- `hostname` - Computer name
- `os` - Operating system
- `user` - User account name
- `ip_address` - IP address (if applicable)

### Event Type & Severity
- `event_type` - Event category (e.g., "process", "auth", "file", "network")
- `severity` - Severity level (0-5)
- `success` - Boolean: whether operation succeeded (1/0, true/false)

### Process Information
- `process_name` - Name of executable
- `command` - Full command line
- `pid` - Process ID
- `ppid` - Parent process ID
- `parent_process` - Parent process name

### File Information
- `filepath` - Full file path
- `message` - Event message text

---

## Pipeline Operators

### 1. `where` - Filter Rows

Filters events based on a boolean expression.

**Syntax:**
```
| where <expression>
```

**Examples:**
```
| where severity >= 3
| where event_type == "process" and success == false
| where user != "SYSTEM"
| where command contains "powershell"
```

### 2. `project` - Select Columns

Selects which columns to include in the results.

**Syntax:**
```
| project field1, field2, field3
| project field1 as alias1, field2 as alias2
```

**Examples:**
```
| project timestamp, hostname, process_name, command
| project user, hostname, timestamp as time
```

If no `project` is specified, all fields are included.

### 3. `sort` - Order Results

Sorts results by one or more fields.

**Syntax:**
```
| sort by field1 asc, field2 desc
```

Default direction is `asc` (ascending).

**Examples:**
```
| sort by timestamp desc
| sort by severity desc, timestamp asc
```

### 4. `take` - Limit Results

Limits the number of returned rows.

**Syntax:**
```
| take <count>
```

**Examples:**
```
| take 100
| take 1000
```

**Limits:**
- Minimum: 1
- Maximum: 10,000

### 5. `distinct` - Unique Values

Returns unique rows based on specified fields.

**Syntax:**
```
| distinct field1
| distinct field1, field2, field3
```

**Examples:**
```
| distinct process_name
| distinct hostname, user
```

### 6. `summarize` - Aggregate Rows

Aggregates rows using functions. Often combined with grouping.

**Syntax:**
```
| summarize agg_func() by field1, field2
```

**Aggregation Functions:**
- `count()` - Count all rows
- `count(field)` - Count non-null values in field
- `dcount(field)` - Count distinct values in field
- `sum(field)` - Sum of values
- `avg(field)` - Average of values
- `min(field)` - Minimum value
- `max(field)` - Maximum value

**Examples:**
```
| summarize count() by process_name
| summarize count(), max(severity) by hostname
| summarize dcount(user) by hostname
```

---

## Expressions & Operators

### Comparison Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `==` | Equal | `severity == 3` |
| `!=` | Not equal | `event_type != "auth"` |
| `<` | Less than | `pid < 1000` |
| `<=` | Less than or equal | `severity <= 3` |
| `>` | Greater than | `pid > 1000` |
| `>=` | Greater than or equal | `severity >= 3` |

### String Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `contains` | Substring search | `command contains "powershell"` |
| `startswith` | Prefix match | `filepath startswith "C:\\" ` |
| `endswith` | Suffix match | `filepath endswith ".exe"` |

**Note:** String operators are case-sensitive in the underlying database.

### Logical Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `and` | Logical AND | `severity >= 3 and event_type == "process"` |
| `or` | Logical OR | `user == "admin" or user == "root"` |
| `not` | Logical NOT | `not success` or `not (event_type == "auth")` |

**Operator Precedence** (highest to lowest):
1. `not`
2. `and`
3. `or`

Use parentheses to override precedence:
```
| where (severity >= 3 and event_type == "process") or (user == "admin")
```

### NULL Handling

The special value `null` represents missing or unknown data.

```
| where command != null        # Has a command
| where command == null        # No command
```

---

## Time Filtering

### Timestamp Comparisons

Use ISO 8601 format for timestamps: `YYYY-MM-DDTHH:MM:SS`

```
| where timestamp >= "2026-08-10T10:00:00"
| where timestamp < "2026-08-11T00:00:00"
```

### Time Windows with `ago()`

Filter for events within a recent time window using `ago()`.

**Syntax:**
```
ago(Nd)  # N days ago
ago(Nh)  # N hours ago
ago(Nm)  # N minutes ago
ago(Ns)  # N seconds ago
```

**Examples:**
```
| where timestamp > ago(1h)      # Last hour
| where timestamp > ago(24h)     # Last day
| where timestamp > ago(7d)      # Last week
```

---

## Complete Examples

### Example 1: Find PowerShell Activity

```
events
| where event_type == "process"
| where process_name == "powershell.exe"
| project timestamp, hostname, user, process_name, command
| sort by timestamp desc
| take 100
```

### Example 2: Authentication Failures by User

```
events
| where event_type == "authentication"
| where success == false
| summarize count() by user
| sort by count desc
| take 50
```

### Example 3: Process Execution Summary

```
events
| where event_type == "process"
| where severity >= 3
| summarize count() as executions, dcount(user) as users by hostname
| sort by executions desc
```

### Example 4: Recent File Access

```
events
| where event_type == "file"
| where filepath endswith ".exe"
| where timestamp > ago(24h)
| project timestamp, hostname, user, filepath
| sort by timestamp desc
```

### Example 5: Distinct Command Patterns

```
events
| where command contains "-nop"
| distinct hostname
```

---

## Error Messages

The query engine provides helpful error messages when queries fail.

### Parse Errors
```
Parse error at line 1, column 15: Unexpected token
```
Indicates a syntax error in the query. Check for:
- Missing pipes between operators
- Misspelled keywords
- Unmatched parentheses

### Validation Errors
```
Unknown field 'proces_name'. Did you mean 'process_name'?
```
Indicates a semantic error. Check for:
- Typos in field names (the engine suggests corrections)
- Invalid operators or values
- Out-of-range limits

### Compilation Errors
```
Invalid field in sort: unknown_field
```
Indicates a field is not available for the operation.

---

## Performance Considerations

### Indexing

The following fields are indexed in the database for fast queries:
- `timestamp`
- `event_type`
- `severity`
- `agent_id`
- `hostname`
- `process_name`
- `user`
- `filepath`

Filtering on indexed fields is very fast. Filtering on other fields scans the entire table.

### Query Optimization Tips

1. **Filter early**: Use `where` before `project` to reduce rows
2. **Use indexed fields**: Prefer filtering on the indexed fields listed above
3. **Limit results**: Always use `take` to cap results
4. **Avoid full-text searches**: `contains` scans all values; `==` is faster

**Good:**
```
events
| where event_type == "process"        # Indexed field
| where severity >= 3                  # Indexed field
| project timestamp, hostname
| take 100
```

**Less Efficient:**
```
events
| project timestamp, hostname, message # Project first (fetches all fields)
| where message contains "error"       # Scans in Python (slow!)
```

---

## Limitations

### Current Version

- Queries must start with `events` (other sources planned)
- No joins or unions
- No subqueries
- No user-defined functions
- Results are limited to 10,000 rows maximum

### Future Enhancements

- Additional time-series operators (e.g., `series`)
- Advanced string functions
- Regular expressions
- Correlation queries across events
- Machine learning-based anomaly detection

---

## API Usage (For Developers)

The query engine can be used programmatically:

```python
from src.query import CyberionQueryEngine
from src.database import CyberionDB

# Initialize
db = CyberionDB()
engine = CyberionQueryEngine(db)

# Execute query
result = engine.execute('events | where severity >= 3 | take 100')

# Access results
print(f"Found {result.row_count} events in {result.execution_time_ms:.1f}ms")
print(f"Columns: {result.columns}")

for row in result.rows:
    print(f"  {row['timestamp']}: {row['event_type']}")
```

---

## Integration with Alert Engine (Future)

After this version, the Alert Engine will use CQL to define detection rules:

```
Rule: PowerShell Execution

Query:
events
| where event_type == "process"
| where process_name == "powershell.exe"

Action:
When query matches → Generate alert with severity 3
```

The query engine is designed to support this workflow without modification.

---

## See Also

- [Architecture Document](./ARCHITECTURE.md) - Query engine internals
- [Test Suite](../tests/test_query_language.py) - Examples and edge cases
- [Database Schema](./database.md) - Field types and indexing
