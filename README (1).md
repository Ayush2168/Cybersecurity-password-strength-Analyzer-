# Password Strength Analyzer — GUI Edition

## Files
| File | Purpose |
|------|---------|
| `main.py` | Entry point — launches Tkinter GUI (falls back to console) |
| `analyzer.py` | Core engine: Password, PasswordAnalyzer, VulnerabilityScanner, PasswordGenerator |
| `crack_time.py` | New: crack-time estimation across 5 attack profiles |
| `models.py` | Person (ABC), User, Admin classes |
| `reports.py` | SecurityReport — JSON + CSV export |
| `common_passwords.txt` | Dictionary of common passwords |

## How to run
```
python main.py
```
Place `common_passwords.txt` in a `data/` subfolder, or keep it beside `main.py`.

## Scoring modes
| Mode | What it measures |
|------|-----------------|
| Mixed (default) | 55% entropy + 45% rule-based complexity |
| Entropy only | Shannon entropy → 0–100 scale |
| Crack time only | Time-to-crack on Offline MD5 (10B/s) → 0–100 scale |

## Crack time attack profiles
- Online (throttled, 1,000 guesses/s)
- Online (unthrottled, 100,000 guesses/s)
- Offline MD5 (10 billion/s)
- Offline bcrypt (10,000/s)
- GPU cluster MD5 (10 trillion/s)
