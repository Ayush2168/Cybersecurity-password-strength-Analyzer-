# crack_time.py - estimates how long it takes to crack a password

import math


ATTACK_PROFILES = {
    "Online (throttled, 1k/s)":      1_000,
    "Online (unthrottled, 100k/s)":  100_000,
    "Offline MD5 (10B/s)":           10_000_000_000,
    "Offline bcrypt (10k/s)":        10_000,
    "GPU cluster MD5 (10T/s)":       10_000_000_000_000,
}


def _format_seconds(seconds: float) -> str:
    if seconds < 0.001:
        return "Instantly (< 1 ms)"
    if seconds < 1:
        return f"{seconds*1000:.1f} milliseconds"
    if seconds < 60:
        n = round(seconds)
        return f"{n} second{'s' if n != 1 else ''}"
    if seconds < 3600:
        n = round(seconds / 60)
        return f"{n} minute{'s' if n != 1 else ''}"
    if seconds < 86400:
        n = round(seconds / 3600)
        return f"{n} hour{'s' if n != 1 else ''}"
    if seconds < 2_592_000:
        n = round(seconds / 86400)
        return f"{n} day{'s' if n != 1 else ''}"
    if seconds < 31_536_000:
        n = round(seconds / 2_592_000)
        return f"{n} month{'s' if n != 1 else ''}"
    if seconds < 3.15e9:
        n = round(seconds / 31_536_000)
        return f"{n} year{'s' if n != 1 else ''}"
    if seconds < 3.15e12:
        return f"{seconds/3.15e9:.1f} thousand years"
    if seconds < 3.15e15:
        return f"{seconds/3.15e12:.1f} million years"
    if seconds < 3.15e18:
        return f"{seconds/3.15e15:.1f} billion years"
    return "Heat death of the universe+"


def _crack_rating(seconds: float) -> tuple[str, str]:
    if seconds < 1:
        return "Instantly", "CRITICAL"
    if seconds < 3600:
        return "Within an hour", "VERY HIGH"
    if seconds < 86400:
        return "Within a day", "HIGH"
    if seconds < 2_592_000:
        return "Within a month", "MEDIUM"
    if seconds < 31_536_000:
        return "Within a year", "LOW"
    if seconds < 3.15e9:
        return "Decades to centuries", "VERY LOW"
    return "Centuries or more", "NEGLIGIBLE"


class CrackTimeEstimator:

    def __init__(self, entropy: float):
        self._entropy = entropy
        self._results: dict[str, dict] = {}

    def estimate_all(self) -> dict[str, dict]:
        self._results = {}
        for profile, guesses_per_sec in ATTACK_PROFILES.items():
            secs = self._estimate_seconds(guesses_per_sec)
            label, danger = _crack_rating(secs)
            self._results[profile] = {
                "guesses_per_second": guesses_per_sec,
                "seconds":            secs,
                "human_readable":     _format_seconds(secs),
                "rating":             label,
                "danger":             danger,
            }
        return self._results

    def _estimate_seconds(self, guesses_per_sec: int) -> float:
        if self._entropy <= 0:
            return 0.0
        avg_guesses = math.pow(2, self._entropy - 1)
        return avg_guesses / guesses_per_sec

    def score_from_crack_time(self, reference_profile: str = "Offline MD5 (10B/s)") -> int:
        if not self._results:
            self.estimate_all()
        secs = self._results.get(reference_profile, {}).get("seconds", 0)
        if secs >= 3.15e16:  return 100   # > trillion years
        if secs >= 3.15e13:  return 90    # > billion years
        if secs >= 3.15e10:  return 80    # > million years
        if secs >= 3.15e7:   return 68    # > 1 year
        if secs >= 2_592_000: return 55   # > 1 month
        if secs >= 86400:    return 40    # > 1 day
        if secs >= 3600:     return 28    # > 1 hour
        if secs >= 60:       return 15    # > 1 minute
        if secs >= 1:        return 8
        return 2

    def print_crack_table(self):
        if not self._results:
            self.estimate_all()
        print(f"\n  {'─'*62}")
        print(f"  {'CRACK TIME ESTIMATES':^62}")
        print(f"  {'─'*62}")
        print(f"  {'Attack Profile':<35} {'Time':<18} {'Danger'}")
        print(f"  {'─'*62}")
        for profile, data in self._results.items():
            print(f"  {profile:<35} {data['human_readable']:<18} {data['danger']}")
        print(f"  {'─'*62}")

    @property
    def results(self) -> dict:
        if not self._results:
            self.estimate_all()
        return self._results
