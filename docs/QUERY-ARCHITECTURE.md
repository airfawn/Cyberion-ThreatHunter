# Cyberion Query Language Architecture

## Overview

The Cyberion Query Language (CQL) is a multi-stage compiler that transforms user-written security queries into parameterized SQL database operations.

```
User Query String
    ↓
Lexer (tokens.py)
    → Tokenize into Token stream
    → Lexer errors for syntax issues
    ↓
Parser (parser.py)
    → Recursive descent parser
    → Produces Abstract Syntax Tree (AST)
    → Parser errors for structural issues
    ↓
Validator (validator.py)
    → Semantic validation
    → Field name checking
    → Operator validation
    → SQL injection prevention
    → Validation errors for semantic issues
    ↓
Compiler (compiler.py)
    → Translates AST to parameterized SQL
    → Builds WHERE/SELECT/GROUP BY/ORDER BY clauses
    → Ensures all values are parameters (NOT inline)
    ↓
QueryEngine (engine.py)
    → Executes compiled SQL against SQLite
    → Returns structured QueryResult
    → Database errors properly wrapped
    ↓
QueryResult
    → rows: List of result dicts
    → columns: Column names
    → execution_time_ms: Query duration
    → row_count: Number of results
```

## Module Breakdown

### 1. tokens.py - Lexer & Tokenization

**Purpose:** Convert a query string into a stream of Token objects.

**Key Classes:**
- `TokenType(Enum)` - All possible token types
- `Token(dataclass)` - A single token with type, value, line, column
- `Lexer` - Tokenizes a query string

**Process:**
1. Iterate through query string character-by-character
2. Group characters into meaningful tokens
3. Recognize keywords (case-insensitive)
4. Handle string literals with escape sequences
5. Recognize operators (`==`, `!=`, `>=`, etc.)
6. Emit EOF token at end

**Example:**
```
Input:  'events | where severity >= 3'
Output: [EVENTS, PIPE, WHERE, IDENTIFIER("severity"), GE, NUMBER("3"), EOF]
```

**Error Handling:**
- Unterminated strings → `SyntaxError`
- Invalid operators → `SyntaxError`
- Unexpected characters → `SyntaxError`

---

### 2. ast.py - Abstract Syntax Tree

**Purpose:** Define node classes representing query structure.

**Key Classes:**
- `ASTNode` - Abstract base for all nodes
- `Query` - Root node (source + pipeline)
- `Source` - Data source (`events`)
- `PipelineOperator` - Base for all operators
  - `WhereOperator` - Filtering
  - `ProjectOperator` - Column selection
  - `SortOperator` - Sorting
  - `TakeOperator` - Result limiting
  - `DistinctOperator` - Unique rows
  - `SummarizeOperator` - Aggregation
- `Expression` - Base for WHERE expressions
  - `Comparison` - Binary comparisons (==, !=, <, >, etc.)
  - `LogicalOp` - AND, OR, NOT
  - `Literal` - Numbers, strings, null
  - `Field` - Field references
  - `FunctionCall` - Functions like ago()
  - `StringOp` - String operators (contains, startswith, endswith)

**No SQL Logic:** These classes represent ONLY the logical query structure, not SQL generation. This separation is critical for:
- Testability (test parsing without SQL)
- Extensibility (add new sources without SQL changes)
- Security (compile step handles SQL injection)

**Example AST:**
```
Query
├── Source: events
└── Pipeline:
    ├── Where(Comparison(Field("severity"), ">=", Literal(3)))
    ├── Project([ProjectColumn("timestamp"), ProjectColumn("hostname")])
    └── Take(100)
```

---

### 3. parser.py - Parser

**Purpose:** Transform token stream into AST.

**Strategy:** Recursive Descent Parsing
- Top-down parsing strategy
- Each rule calls sub-rules for nested structures
- Clear error messages with line/column info

**Key Methods:**
- `parse()` - Entry point, validates EOF
- `parse_source()` - Expect `events`
- `parse_pipeline()` - Parse `| operator` sequences
- `parse_operator()` - Dispatch to appropriate operator parser
- `parse_expression()` - Recursive expression parsing
  - `parse_or_expression()` - OR (lowest precedence)
  - `parse_and_expression()` - AND
  - `parse_not_expression()` - NOT
  - `parse_comparison()` - Comparisons & string operators
  - `parse_primary()` - Literals, fields, parenthesized expressions

**Operator Precedence** (highest to lowest):
1. Primary (literals, fields, parentheses)
2. NOT
3. Comparison operators and string operators
4. AND
5. OR

**Error Handling:**
- Expected token missing → `ParseError` with context
- Unexpected token → `ParseError` with suggestion
- All errors include line/column information

**Example:**
```
Input tokens:  events | where severity >= 3
Parser produces:
  Query(
    source=Source("events"),
    pipeline=[
      WhereOperator(
        condition=Comparison(
          left=Field("severity"),
          operator=">=",
          right=Literal(3)
        )
      )
    ]
  )
```

---

### 4. validator.py - Semantic Validation

**Purpose:** Check that AST is semantically correct before compilation.

**Validations:**
1. **Field Names** - Must exist in SCHEMA_COLUMNS
   - Suggests corrections for typos (Levenshtein distance)
   - Example: `proces_name` → suggests `process_name`

2. **Operators** - Must be valid for their context
   - Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
   - Logical: `and`, `or`, `not`
   - String: `contains`, `startswith`, `endswith`

3. **Values** - Must be appropriate types
   - Numbers must be integers or floats
   - Take count must be 1-10,000

4. **Aggregation Functions** - Must be recognized
   - `count()`, `count(field)`, `dcount()`, `sum()`, `avg()`, `min()`, `max()`
   - Some functions require field arguments

5. **NULL Handling** - `IS NULL` and `IS NOT NULL` are recognized

6. **Time Functions** - `ago()` argument validation
   - Pattern: `\d+[smhd]` (number + unit)

**Error Messages:**
All errors are collected and returned together, providing complete feedback.

**Example:**
```
Query: events | where severity >= 3 and proces_name == "cmd.exe"

Validation Error:
  Unknown field 'proces_name'. Did you mean 'process_name'?
```

---

### 5. compiler.py - SQL Code Generation

**Purpose:** Transform validated AST into parameterized SQL.

**Key Principle:** Values are NEVER in SQL strings. All user input becomes parameters.

**Process for Each Operator:**

**WHERE:**
```
Comparison(Field("severity"), ">=", Literal(3))
  ↓
"WHERE severity >= ?"
params: [3]
```

**PROJECT:**
```
ProjectOperator([ProjectColumn("timestamp"), ProjectColumn("hostname")])
  ↓
"SELECT timestamp, hostname"
```

**SORT:**
```
SortOperator([SortField("severity", "desc")])
  ↓
"ORDER BY severity DESC"
```

**TAKE:**
```
TakeOperator(100)
  ↓
"LIMIT 100"
```

**DISTINCT:**
```
DistinctOperator(["process_name"])
  ↓
"SELECT DISTINCT process_name"
```

**SUMMARIZE:**
```
SummarizeOperator(
  aggregations=[Aggregation("count()", None)],
  group_by=["process_name"]
)
  ↓
"SELECT process_name, COUNT(*) FROM events GROUP BY process_name"
```

**String Operators:**
```
StringOp("command", "contains", "powershell")
  ↓
"command LIKE '%' || ? || '%'"
params: ["powershell"]
```

**NULL Handling:**
```
Comparison(Field("command"), "==", Literal(None))
  ↓
"command IS NULL"
(No parameter added)
```

**Time Functions (ago):**
```
FunctionCall("ago", ["1h"])
  ↓
Calculates: datetime.utcnow() - timedelta(hours=1)
"datetime_value" as string parameter
params: ["2026-08-10T15:32:00"]
```

**SQL Injection Prevention:**
1. Field names validated against SCHEMA_COLUMNS before use
2. Operators come from hardcoded internal mappings
3. Values become `?` placeholders with parameters separate
4. All user input goes into `self.params` list

Example SQL injection attempt:
```
Input:  events | where process == "cmd' OR '1'='1"
Lexer/Parser: Creates Literal("cmd' OR '1'='1")
Compiler: "WHERE process == ?", params: ["cmd' OR '1'='1"]
SQLite: Executes with parameter, string is treated as literal value
Result: NO SQL INJECTION
```

---

### 6. engine.py - Query Engine

**Purpose:** Orchestrate the entire pipeline and provide a clean API.

**Key Classes:**
- `CyberionQueryEngine` - Main public API
- `QueryResult` - Result object with metadata
- `QueryEngineError` - Exception wrapper

**Public API:**
```python
engine = CyberionQueryEngine(database)
result = engine.execute("events | where severity >= 3 | take 100")

# result.rows: List[Dict]
# result.columns: List[str]
# result.execution_time_ms: float
# result.query_text: str
# result.compiled_sql: str
```

**Pipeline:**
1. **Parse:** `Parser.from_string()` → AST or ParseError
2. **Validate:** `QueryValidator().validate()` → ValidationError if invalid
3. **Compile:** `QueryCompiler().compile()` → CompiledQuery or CompileError
4. **Execute:** `_execute_sql()` → (rows, columns) or database error
5. **Wrap:** Create QueryResult with metadata

**Error Handling:**
All exceptions are caught and re-raised as `QueryEngineError` with human-readable messages.

---

## Security Architecture

### SQL Injection Prevention

**Defense Layers:**

1. **Lexer** - Only recognizes specific tokens
   - Unknown characters are errors
   - String escape sequences are validated

2. **Parser** - Builds AST from tokens
   - No SQL strings created yet
   - Structural validation only

3. **Validator** - Semantic checks
   - Field names checked against whitelist (VALID_FIELDS)
   - Operators checked against whitelist
   - Function names checked against whitelist

4. **Compiler** - Parameterized SQL generation
   - Field names taken ONLY from validated sources
   - Operators taken ONLY from hardcoded mapping
   - Values ALWAYS become `?` placeholders
   - Parameters stored separately in list

5. **Database Driver (SQLite)** - Parameterized execution
   - SQLite executes SQL + parameters separately
   - Parameters are never interpreted as SQL code

**Test Coverage:**
```python
# Direct injection attempts all fail safely
"x' OR 1=1 --"  → Parameter, not SQL
"' UNION SELECT * --"  → Parameter, not SQL
"'; DROP TABLE events; --"  → Parameter, not SQL
```

### Field Validation

All queryable fields are whitelisted in `QueryValidator.VALID_FIELDS`:
```python
VALID_FIELDS = {
    "id", "timestamp", "received_at", "source", "agent_id", "agent_name",
    "hostname", "os", "event_type", "severity", "success",
    "pid", "ppid", "process_name", "parent_process",
    "user", "filepath", "command", "message", "ip_address",
}
```

Users CANNOT query:
- System columns (auto-generated)
- JSON-embedded data
- Dynamic fields not in schema

---

## Performance Considerations

### Indexing

Indexed fields (fast queries):
- `timestamp` - Time-based filtering
- `event_type` - Event type filtering
- `severity` - Severity-based queries
- `agent_id`, `hostname` - Source filtering
- `process_name` - Process queries
- `user`, `filepath` - User/file queries

### Query Optimization

**Good:**
```
events
| where event_type == "process"  # Indexed field
| where severity >= 3            # Indexed field
| take 100                       # Limits results
```

**Poor:**
```
events
| project *                      # Fetches all rows first
| where message contains "error" # Filters in Python (slow!)
```

The compiler generates SQL that pushes filtering into SQLite:
```
# Good: Filtering in SQL WHERE clause
SELECT * FROM events WHERE event_type = ? AND severity >= ? LIMIT 100

# Compiler never generates:
SELECT * FROM events LIMIT 99999999  # Then filter in Python
```

### Result Limits

Maximum result limit: **10,000 rows**

This prevents:
- Accidentally loading entire event database
- Out-of-memory errors
- GUI table performance degradation

User can:
- Use more specific WHERE clauses
- Execute multiple queries with different LIMIT values
- Use aggregation (summarize) to condense results

---

## Testing Strategy

### Test Files

**tests/test_query_language.py** - 47 comprehensive tests

**Test Coverage:**

1. **Lexer Tests** (7 tests)
   - Simple queries
   - String literals with escapes
   - All operators
   - Keywords
   - Error cases

2. **Parser Tests** (12 tests)
   - WHERE clauses
   - String comparisons
   - Logical operators
   - Parenthesized expressions
   - All pipeline operators
   - Error cases

3. **Validator Tests** (8 tests)
   - Field validation
   - Field suggestions
   - Value validation
   - Range validation
   - NULL handling
   - Aggregation validation

4. **Compiler Tests** (14 tests)
   - SQL generation for each operator
   - Parameterized SQL verification
   - String operators
   - NULL handling
   - SQL injection attempts

5. **Integration Tests** (2 tests)
   - End-to-end query execution
   - Error handling

### Test Patterns

```python
# Unit test: Verify parser output
query = Parser.from_string("events | where severity >= 3").parse()
assert len(query.pipeline) == 1
assert isinstance(query.pipeline[0], WhereOperator)

# Security test: Verify injection prevention
compiled = compiler.compile(ast)
assert "' OR 1=1" not in compiled.sql
assert "' OR 1=1" in compiled.params

# Integration test: Execute real query
result = engine.execute("events | where severity >= 3 | take 100")
assert result.row_count <= 100
```

---

## Extension Points

### Adding New Operators

To add a new pipeline operator:

1. **Define AST Node** in `ast.py`
   ```python
   @dataclass
   class NewOperator(PipelineOperator):
       field: str
   ```

2. **Add Lexer Support** in `tokens.py` if needed

3. **Add Parser** in `parser.py`
   ```python
   def parse_new_operator(self) -> NewOperator:
       self.expect(TokenType.NEWKEYWORD)
       ...
   ```

4. **Add Validator** in `validator.py`
   ```python
   def _validate_new_operator(self, op: NewOperator):
       self._validate_field(op.field)
   ```

5. **Add Compiler** in `compiler.py`
   ```python
   def _compile_new_operator(self, op: NewOperator) -> str:
       # Generate SQL
   ```

6. **Add Tests** in `tests/test_query_language.py`

### Adding New Functions

To add a new function (like `ago()`):

1. Add to `FunctionCall` handling in parser
2. Add validation in validator
3. Add compilation in compiler
4. Add tests

---

## Future Enhancements

### Planned Features

- **Time-series operators** - `series`, `bin`
- **Advanced string functions** - Regex, case conversion
- **Correlation queries** - Join multiple event sources
- **User-defined variables** - `let x = ...`
- **Subqueries** - Nested queries
- **Additional aggregations** - Percentiles, standard deviation
- **Multiple sources** - `alerts | ...`, `processes | ...`

### Alert Engine Integration

After KQL implementation, the Alert Engine will use CQL:

```python
rule = AlertRule(
    name="PowerShell Execution",
    query="events | where process_name == 'powershell.exe'",
    severity=3,
    action="generate_alert"
)

# Alert Engine reuses the exact same query_engine
for event in database:
    if engine.matches(rule.query, event):
        create_alert(rule, event)
```

The query engine is designed to support this without modification.

---

## Debugging

### Enable SQL Logging

```python
result = engine.execute("events | where severity >= 3")
print(result.compiled_sql)
print(result.execution_time_ms)
```

### Error Types

- `ParseError` - Syntax error in query
- `ValidationError` - Semantic error (field name, operator, etc.)
- `CompileError` - SQL generation error (shouldn't happen after validation)
- `QueryEngineError` - Any error during execution (wraps others)

### Common Issues

**"Unknown field 'proces_name'"**
- Typo in field name
- Use suggestions provided by validator

**"Unexpected token"**
- Syntax error in query
- Check pipe placement, operator spelling

**"take() limit too large"**
- Result limit exceeded 10,000
- Use WHERE clause to filter fewer results

---

## References

- [User Documentation](./query-language.md)
- [Test Suite](../tests/test_query_language.py)
- [Main GUI Integration](../src/main.py)
