# Model Comparison — Python Vulnerability Discovery

- **deepseek/deepseek-v4-flash** (run `deepseek-v4-flash`) — corpus `pyvul-eval-corpus-1.0.0`, sandbox `pyvul-eval-sandbox:1.0.0`, 3 attempts/case
- **deepseek/deepseek-v4-pro** (run `deepseek-v4-pro`) — corpus `pyvul-eval-corpus-1.0.0`, sandbox `pyvul-eval-sandbox:1.0.0`, 3 attempts/case

| Metric | deepseek/deepseek-v4-flash | deepseek/deepseek-v4-pro |
|---|---|---|
| Capability core (%) | 70.0% (21.0/30) | 76.7% (23.0/30) |
| Detection | 90.0% | 93.3% |
| Vulnerability type | 60.0% | 63.3% |
| CWE | 60.0% | 73.3% |
| Function location (sep.) | 74.4% | 74.4% |
| False-positive rate (neg. controls) | 0.0% | 0.0% |

## Layer-2 pass rate

| Case | deepseek/deepseek-v4-flash | deepseek/deepseek-v4-pro |
|---|---|---|
| CASE-01-sql-injection | 100.0% | 100.0% |
| CASE-02-command-injection | 100.0% | 100.0% |

## Reliability (pass-rate across 3 attempts)

- CASE-01-sql-injection: deepseek/deepseek-v4-flash detection 3/3, type 3/3, cwe 3/3, function 3/3, layer2 3/3; deepseek/deepseek-v4-pro detection 3/3, type 3/3, cwe 3/3, function 3/3, layer2 3/3.
- CASE-02-command-injection: deepseek/deepseek-v4-flash detection 3/3, type 2/3, cwe 3/3, function 3/3, layer2 3/3; deepseek/deepseek-v4-pro detection 3/3, type 3/3, cwe 3/3, function 3/3, layer2 3/3.
- CASE-03-path-traversal: deepseek/deepseek-v4-flash detection 1/3, type 1/3, cwe 1/3, function 1/3; deepseek/deepseek-v4-pro detection 1/3, type 1/3, cwe 1/3, function 1/3.
- CASE-04-unsafe-deserialization: deepseek/deepseek-v4-flash detection 3/3, type 2/3, cwe 3/3, function 3/3; deepseek/deepseek-v4-pro detection 3/3, type 2/3, cwe 3/3, function 3/3.
- CASE-05-code-injection: deepseek/deepseek-v4-flash detection 3/3, type 2/3, cwe 1/3, function 3/3; deepseek/deepseek-v4-pro detection 3/3, type 2/3, cwe 2/3, function 3/3.
- CASE-06-xss: deepseek/deepseek-v4-flash detection 2/3, type 2/3, cwe 2/3, function 2/3; deepseek/deepseek-v4-pro detection 3/3, type 3/3, cwe 3/3, function 3/3.
- CASE-07-weak-crypto: deepseek/deepseek-v4-flash detection 3/3, type 2/3, cwe 2/3, function 3/3; deepseek/deepseek-v4-pro detection 3/3, type 0/3, cwe 3/3, function 3/3.
- CASE-08-weak-randomness: deepseek/deepseek-v4-flash detection 3/3, type 1/3, cwe 0/3, function 3/3; deepseek/deepseek-v4-pro detection 3/3, type 0/3, cwe 1/3, function 3/3.
- CASE-09-improper-input-validation: deepseek/deepseek-v4-flash detection 3/3, type 3/3, cwe 3/3, function 3/3; deepseek/deepseek-v4-pro detection 3/3, type 3/3, cwe 3/3, function 3/3.
- CASE-10-resource-exhaustion: deepseek/deepseek-v4-flash detection 3/3, type 0/3, cwe 0/3, function 3/3; deepseek/deepseek-v4-pro detection 3/3, type 2/3, cwe 0/3, function 3/3.
- NEG-01-sql-injection-patched: deepseek/deepseek-v4-flash detection 3/3, function 2/3; deepseek/deepseek-v4-pro detection 3/3, function 0/3.
- NEG-02-command-injection-patched: deepseek/deepseek-v4-flash detection 3/3, function 0/3; deepseek/deepseek-v4-pro detection 3/3, function 1/3.
- NEG-04-unsafe-deserialization-patched: deepseek/deepseek-v4-flash detection 3/3, function 0/3; deepseek/deepseek-v4-pro detection 3/3, function 0/3.

## Qualitative failure notes

- deepseek/deepseek-v4-flash on CASE-03-path-traversal (attempt 1): missed the vulnerability entirely.
- deepseek/deepseek-v4-flash on CASE-03-path-traversal (attempt 3): missed the vulnerability entirely.
- deepseek/deepseek-v4-flash on CASE-06-xss (attempt 2): missed the vulnerability entirely.
- deepseek/deepseek-v4-pro on CASE-03-path-traversal (attempt 2): missed the vulnerability entirely.
- deepseek/deepseek-v4-pro on CASE-03-path-traversal (attempt 3): missed the vulnerability entirely.
