# C Source Code Comment Quality Assurance

## Overview

This document defines standards and procedures for automated review
and correction of comments in C source files (`.c` extension only).
The objective is to maintain consistent, professional, and
grammatically correct documentation throughout the codebase.

## Scope and Applicability

### Target Files
- **File Extension**: `.c` files only
- **Comment Types**: Single-line (`//`) and multi-line (`/* */`)
- **Exclusions**: Header files (`.h`), code logic, and non-comment
  content

### Quality Dimensions

The checker evaluates comments across six quality dimensions:

1. Syntax compliance
2. Orthographic accuracy (spelling)
3. Capitalization and punctuation
4. Grammatical correctness
5. Line length constraints
6. Terminology consistency

## Quality Standards

### 1. Syntax Requirements

**Objective**: Ensure syntactically valid comment structures.

- Comment delimiters must be properly paired (`//` or `/* */`)
- Multi-line comments must not be left unclosed
- Comment placement must not interfere with code compilation
- Multi-line comments must follow the standard format:
  ```c
  /*
   * First line of comment.
   * Second line of comment.
   */
  ```
  Each intermediate line must begin with a single asterisk (`*`)
  aligned with the opening delimiter

### 2. Spelling Standards

**Objective**: Maintain professional orthographic quality.

- Validate words against standard English dictionary
- Maintain allowlist for:
  - Technical terminology (e.g., "mutex", "semaphore")
  - Function and variable identifiers
  - Project-specific terms
  - Standard abbreviations
- Flag unrecognized terms for manual review
- Build project-specific dictionary through iterative learning

### 3. Capitalization and Punctuation Rules

**Objective**: Ensure proper sentence structure and readability.

- Sentence-initial words must begin with uppercase letter
- All declarative sentences must terminate with period (`.`)
- Interrogative sentences must end with question mark (`?`)
- Exclamatory sentences must end with exclamation mark (`!`)
- New sentences following terminal punctuation must begin with
  uppercase
- **Exception**: Preserve original case for code identifiers
  (function names, variable names, constants)

### 4. Grammar Standards

**Objective**: Maintain grammatical correctness in technical
documentation.

- Verify subject-verb agreement
- Prefer present tense for function descriptions
  - Correct: "Returns the sum of two integers."
  - Avoid: "Will return the sum of two integers."
- Ensure complete sentences where appropriate
- Identify and flag sentence fragments or run-on sentences
- Validate article usage (a, an, the)
- Apply context-aware rules for technical writing conventions

### 5. Line Length Constraints

**Objective**: Maintain readability and comply with coding standards.

- Maximum line length: 79 characters (including comment delimiters)
- Break long comments at natural boundaries:
  - Prefer breaking at spaces
  - Break after punctuation when possible
  - Maintain semantic coherence across line breaks
- Preserve proper indentation when wrapping comments
- Align continuation lines appropriately

### 6. Consistency Requirements

**Objective**: Ensure uniform terminology and style across codebase.

- Standardize terminology for equivalent concepts
  - Example: "Initialize" vs "Initialise" (prefer American English)
- Maintain consistent phrasing for similar operations
- Track terminology usage patterns across files
- Flag inconsistent comment styles within individual files
- Build and maintain project terminology glossary

## Operational Workflow

### Phase 1: Discovery and Analysis

1. **File Enumeration**: Recursively scan target directory for `.c`
   files
2. **Comment Extraction**: Parse and extract all comment blocks
3. **Quality Assessment**: Evaluate each comment against all six
   quality dimensions
4. **Issue Classification**: Categorize identified issues by type
   and severity

### Phase 2: Reporting

Generate structured report containing:

- File path (relative to project root)
- Line number (1-indexed)
- Issue category (syntax/spelling/capitalization/grammar/length/
  consistency)
- Current comment text
- Suggested correction
- Rationale for suggested change (when non-obvious)

**Report Format**:
```
File: src/network/connection.c
Line: 127
Category: Grammar
Severity: Medium
Current: // The function process incoming connections
Suggested: // The function processes incoming connections.
Rationale: Subject-verb agreement (singular subject requires
           singular verb)

File: src/utils/buffer.c
Line: 89
Category: Length
Severity: Low
Current: // This utility function allocates and initializes a
         // buffer structure with the specified size parameter
Suggested: // This utility function allocates and initializes a
           // buffer structure with the specified size parameter.
Rationale: Missing terminal punctuation; line length compliant

File: src/core/init.c
Line: 45
Category: Consistency
Severity: Low
Current: // Initialise the subsystem
Note: Project standard uses "Initialize" (American English)
Suggested: // Initialize the subsystem.
```

### Phase 3: Correction

1. **Review**: Present suggested changes to developer
2. **Confirmation**: Obtain explicit approval for each change or
   batch
3. **Application**: Apply approved corrections atomically
4. **Verification**: Confirm successful application
5. **Summary**: Generate statistics on corrections applied

## Implementation Guidelines

### Preservation Requirements

The following elements must be preserved unchanged:

- Code formatting and indentation
- Comment alignment relative to code
- Technical acronyms (API, HTTP, SQL, TCP, etc.)
- URLs and file paths
- Code examples embedded in comments
- Intentional stylistic choices (when documented)

### Context-Aware Processing

- **Technical Writing**: Apply lenient grammar rules appropriate
  for technical documentation
- **Abbreviations**: Allow standard abbreviations (e.g., i.e.,
  etc., vs.)
- **Line Breaking**: Prioritize readability over strict character
  limits
- **Terminology**: Build project-specific dictionary through
  analysis of existing codebase

### Quality Assurance

- **Backup**: Create backup before applying any modifications
- **Atomic Operations**: Apply changes transactionally
- **Rollback Capability**: Maintain ability to revert changes
- **Audit Trail**: Log all modifications with timestamps
- **Validation**: Re-scan modified files to verify corrections

## Examples

### Example 1: Comprehensive Correction

**Before**:
```c
// this function calculates the sum
int add(int a, int b) {
    /* returns the result of a+b
       note: handles negative numbers */
    return a + b;
}
```

**After**:
```c
// This function calculates the sum.
int add(int a, int b) {
    /*
     * Returns the result of a+b.
     * Note: Handles negative numbers.
     */
    return a + b;
}
```

**Issues Corrected**:
- Capitalization: "this" → "This"
- Punctuation: Added terminal period
- Syntax: Reformatted multi-line comment with asterisks
- Capitalization: "returns" → "Returns", "note" → "Note"

### Example 2: Length and Grammar

**Before**:
```c
// This function are responsible for processing all incoming network requests and validating them
void process_request(struct request *req) {
    // validate request
}
```

**After**:
```c
// This function is responsible for processing all incoming
// network requests and validating them.
void process_request(struct request *req) {
    // Validate request.
}
```

**Issues Corrected**:
- Grammar: "are" → "is" (subject-verb agreement)
- Length: Split line at 79 characters
- Capitalization: "validate" → "Validate"
- Punctuation: Added terminal periods

### Example 3: Consistency Across Files

**Before** (file1.c):
```c
// Initialise the connection.
void init_conn(void) { }
```

**Before** (file2.c):
```c
// Initialize the buffer.
void init_buffer(void) { }
```

**After** (standardized):
```c
// Initialize the connection.
void init_conn(void) { }

// Initialize the buffer.
void init_buffer(void) { }
```

**Issues Corrected**:
- Consistency: Standardized to American English spelling

## Usage Instructions

### Command-Line Interface

```bash
# Analyze single file
comment-checker analyze src/main.c

# Analyze directory recursively
comment-checker analyze src/ --recursive

# Apply fixes with confirmation
comment-checker fix src/ --interactive

# Generate report only
comment-checker report src/ --output=report.txt

# Batch mode (auto-apply safe fixes)
comment-checker fix src/ --batch --safe-only
```

### Configuration

Create `.comment-checker.conf` in project root:

```ini
[general]
max_line_length = 79
language = en_US

[spelling]
dictionary = project-terms.txt
ignore_case = false

[consistency]
prefer_american_english = true
build_glossary = true

[grammar]
strict_mode = false
allow_fragments = true
```

## Maintenance and Evolution

- **Dictionary Updates**: Regularly review and update technical
  term allowlist
- **Rule Refinement**: Adjust rules based on project conventions
- **False Positive Tracking**: Monitor and reduce false positive
  rate
- **Performance Optimization**: Ensure scalability for large
  codebases
- **Integration**: Consider CI/CD pipeline integration for
  automated checks

## References

- C Coding Standards (project-specific)
- The Elements of Style (Strunk & White)
- Technical Writing Best Practices
- Project Contribution Guidelines