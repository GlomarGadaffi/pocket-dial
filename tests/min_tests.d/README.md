# Test-count floor contributions (#467)

The host suite must run at least **`tests/EXPECTED_MIN_TESTS` + every number
in this directory** tests, or CI's *Verify Test Count* step fails
(`tests/tools/check_test_count.py`).

**A PR that adds tests** adds one file here, named after its issue:

```
tests/min_tests.d/470-cdr-nvs-blob.txt
```

containing the number of tests it adds (comments with `#` are fine):

```
# CdrPersistBlob_test.cpp: 3 + ResetGuard: 1
4
```

**A PR that removes tests on purpose** adds a negative number (`-2`), so the
reduction is still visible in the diff.

Never edit the base number in a feature PR. Separate files never conflict,
so PRs merge in any order; editing the one shared number is what made every
second PR need a rebase. Once this directory gets long, a single PR on
`main` runs `python3 tests/tools/check_test_count.py --compact`, which folds
the files into the base and deletes them.

Names must match `<issue>-<slug>.txt` (lowercase). Anything else, or a file
without an integer, fails the check closed.
