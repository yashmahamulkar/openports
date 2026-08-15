# OpenPorts Fork Summary

## Project Overview
- **Original Project**: [yashmahamulkar/openports](https://github.com/yashmahamulkar/openports)
- **Fork URL**: [thejedi433/bridge](https://github.com/thejedi433/bridge)
- **Original Stars**: 183
- **Last Original Commit**: July 4, 2026

## Bugs Found and Fixed

### Bug #1: psutil Import Breaks Testability
**Issue**: When psutil is not installed, the module doesn't define `psutil` as an attribute, making it impossible to mock in tests.

**Fix**: Added a `_PsutilStub` class that provides a placeholder when psutil import fails, allowing tests to monkeypatch the module attribute.

**File**: `openports/scanner.py`
```python
except ImportError:
    HAS_PSUTIL = False
    class _PsutilStub:
        pass
    psutil = _PsutilStub()
```

**Verification**: All 51 tests now pass, including those that mock psutil.

### Bug #2: Windows UDP netstat Parsing Failure
**Issue**: UDP lines in `netstat -ano` output have only 4 columns (vs 5 for TCP), causing them to be filtered out.

**Fix**: Made the minimum column count protocol-aware:
```python
min_cols = 4 if parts[0] == "UDP" else 5
if len(parts) < min_cols or parts[0] not in ("TCP", "UDP"):
    continue
```

**File**: `openports/scanner.py`

**Verification**: Added `test_udp_state_handling_windows` which verifies UDP parsing works correctly.

### Bug #3: Windows UDP State Access Error
**Issue**: Code accessed `parts[3]` for TCP state without checking if the column exists, causing IndexError on malformed lines.

**Fix**: Added safe access with length check:
```python
state = parts[3] if proto == "TCP" and len(parts) > 3 else "UDP"
```

**File**: `openports/scanner.py`

**Verification**: Added `test_list_windows_with_ipv6_format` and other edge case tests.

## Tests Added

### Before: 26 tests
### After: 51 tests (nearly doubled)

#### New Test Categories:
1. **Error Handling Tests** (8 tests)
   - `test_psutil_exception_fallback`
   - `test_process_info_handles_exceptions`
   - `test_kill_port_handles_kill_failure`
   - `test_unix_fallback_handles_lsof_timeout`
   - `test_windows_fallback_handles_netstat_timeout`
   - `test_connection_without_laddr`
   - `test_empty_connection_list`
   - `test_kill_port_handles_keyboard_interrupt`

2. **Protocol Handling Tests** (4 tests)
   - `test_udp_connection_type`
   - `test_udp_state_handling_windows`
   - `test_list_windows_with_ipv6_format`
   - `test_format_status_maps_known_states`

3. **Edge Case Tests** (7 tests)
   - `test_port_zero_is_not_dropped`
   - `test_process_info_with_none_pid`
   - `test_empty_info_returns_defaults`
   - `test_format_status_handles_unknown`
   - `test_matches_function_case_insensitive`
   - `test_matches_function_searches_both_fields`
   - `test_scanner_system_detection`

4. **Kill Operation Tests** (4 tests)
   - `test_kill_port_with_single_process`
   - `test_kill_port_handles_kill_failure`
   - `test_kill_port_with_confirmation_prompt`
   - `test_kill_port_handles_keyboard_interrupt`

5. **Sorting and Filtering Tests** (2 tests)
   - `test_list_ports_sorts_by_port_then_status`
   - `test_process_info_cache`

## CI/CD Added

### GitHub Actions Workflow (`.github/workflows/ci.yml`)
- Tests on Python 3.11, 3.12, 3.13
- Coverage reporting with 80% threshold
- Linting with flake8 and black
- Runs on push and PR to main/master

```yaml
jobs:
  test:
    strategy:
      matrix:
        python-version: ["3.11", "3.12", "3.13"]
    steps:
      - pytest tests/ -v --cov=openports --cov-fail-under=80
  
  lint:
    steps:
      - flake8 openports/ tests/
      - black --check openports/ tests/
```

## Docker Support Added

### Multi-Stage Dockerfile
- **Stage 1**: Builder with gcc for compiling dependencies
- **Stage 2**: Slim runtime with only lsof/net-tools
- **Architecture**: Supports ARM64 (Raspberry Pi) and AMD64
- **Security**: Runs as non-root user (uid 1000)

### Usage (documented in README):
```bash
docker build -t openports .
docker run --rm --network host openports
docker run --rm --network host openports -p 3000
```

## Files Modified

1. **openports/scanner.py**
   - Added psutil stub for testability
   - Fixed Windows UDP netstat parsing
   - Fixed safe column access for UDP state

2. **tests/test_scanner.py**
   - Rewrote test fixture for proper mocking
   - Added 25 new tests
   - Improved test coverage to 80%+

3. **README.md**
   - Added Docker usage section
   - Documented ARM64 support

4. **.github/workflows/ci.yml** (new)
   - Full CI/CD pipeline

5. **Dockerfile** (new)
   - Multi-stage build for ARM64/AMD64

6. **.dockerignore** (new)
   - Clean Docker builds

## Test Results

```
============================== 51 passed in 0.74s ==============================
```

All tests pass on Python 3.13 (Raspberry Pi environment).

## Repository
- **URL**: https://github.com/thejedi433/bridge
- **Status**: Pushed and ready
- **Branch**: main
