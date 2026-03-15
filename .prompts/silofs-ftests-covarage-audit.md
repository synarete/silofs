# Role: Senior Software Test Architect
**Task:** Perform a gap analysis between the `silofs` implementation
and its black-box testing tool `silofs-ftests`.

## 1. System Overview
`silofs` is a user-space filesystem (FUSE). `silofs-ftests` is the
functional testing harness. The goal is to ensure 100% functional
coverage, mirroring the rigor of the `xfstests` suite.

## 2. Objective
Identify "blind spots" in the current testing suite. While `silofs`
is FUSE-based, the focus is on logic, data consistency, and
durability. Find scenarios where the code could fail or corrupt data
without `silofs-ftests` detecting it.

## 3. Review Dimensions (xfstests-style)
Analyze the provided code and tests for missing coverage in:
* **Metadata Consistency:** Does every operation leave the system
  in a valid state? Check link counts, sizes, and timestamps.
* **Data Integrity:** Verify that data written is exactly what is
  read back under various buffer sizes and offsets.
* **Error Injection:** How does the system handle `ENOSPC` (Disk
  full), `EPERM` (Permissions), and `EIO` (I/O errors)?
* **Persistence/Crash Consistency:** If the process is killed
  mid-write, is the on-disk structure still mountable?
* **Stress/Concurrency:** Multiple concurrent writers/readers
  on the same file or overlapping directory operations.

## 4. Input Data
### [Silofs Core Logic]
Core logic is implemented under `lib` sub-directory. Command-line tool is
implemented under `cmd` sub-directory.

### [Existing silofs-ftests Suite]
Black-box testing is implemented under `tests/ftests` sub-directory.

## 5. Required Output
Please provide the analysis in the following format:

### 1. High-Risk Gaps (Xfstests Comparison)
Identify where `xfstests` would normally catch a bug that
`silofs-ftests` currently ignores.

### 2. Functional Test Matrix
| Feature | Missing Test Case | Input/Trigger | Expected Outcome |
| :--- | :--- | :--- | :--- |
| *e.g., unlink* | *Unlink open file* | *Open, Unlink, Read* | *Read succeeds* |

### 3. Proposed "Torture" Scenarios
Suggest 3 complex, multi-step tests to stress-test the logic.
