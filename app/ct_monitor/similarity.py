"""Domain look-alike (typosquatting / homoglyph) detection.

For a protected domain and a candidate domain found in Certificate
Transparency logs, a similarity score (0-100) is computed from string
distance, edit operations, character overlap and a visual homoglyph check.
The maximum is taken and floored at 80 when the candidate starts with the
protected name (e.g. certwatchlab-login).

Risk levels (project report Table 4.1):
    Critical >= 90, High >= 75, Medium >= 55, else Low
"""
import unicodedata
from difflib import SequenceMatcher

# Characters that look alike to a human reader.
_HOMOGLYPH_GROUPS = [
    set("0oO"), set("1lI|"), set("5sS"), set("8bB"), set("2zZ"),
    set("6gG"), set("9qQ"), set("mw"), set("rn"), set("vv"),
]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _strip_tld(domain: str) -> str:
    return domain.rsplit(".", 1)[0] if "." in domain else domain


def string_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio() * 100


def edit_similarity(a: str, b: str) -> float:
    dist = _levenshtein(a, b)
    return max(0.0, (1 - dist / max(len(a), len(b))) * 100)


def overlap_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return len(set(a) & set(b)) / max(len(set(a)), len(set(b))) * 100


def homoglyph_score(a: str, b: str) -> float:
    """100 when the two names are identical after replacing look-alike
    characters with a canonical member of their group."""
    def canon(s):
        s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
        out = []
        for ch in s.lower():
            for group in _HOMOGLYPH_GROUPS:
                if ch in group:
                    out.append(sorted(group)[0])
                    break
            else:
                out.append(ch)
        return "".join(out)
    return 100.0 if (canon(a) == canon(b) and a != b) else 0.0


def risk_level_for(score: int) -> str:
    if score >= 90:
        return "Critical"
    if score >= 75:
        return "High"
    if score >= 55:
        return "Medium"
    return "Low"


def analyze_similarity(protected: str, detected: str):
    """Return (score:int, risk_level:str, reason:str).

    Exact matches and real subdomains of the protected domain are ignored
    (score 0) - they are legitimate, not look-alikes.
    """
    protected, detected = protected.lower().strip(), detected.lower().strip()
    if detected == protected or detected.endswith("." + protected):
        return 0, "Low", "Exact match or legitimate subdomain - ignored"

    p, d = _strip_tld(protected), _strip_tld(detected)
    scores = {
        "string": string_similarity(p, d),
        "edit": edit_similarity(p, d),
        "overlap": overlap_similarity(p, d),
        "homoglyph": homoglyph_score(p, d),
    }
    score = max(scores.values())
    method = max(scores, key=scores.get)
    # A candidate that merely prepends/appends words to the protected name
    # (certwatchlab-login.com) is highly suspicious even if distance is large.
    if p in d and score < 80:
        score, method = 80, "contains"
    score = int(round(score))
    reason = (f"{method} similarity between '{p}' and '{d}' "
              f"(string={scores['string']:.0f}, edit={scores['edit']:.0f}, "
              f"overlap={scores['overlap']:.0f}, homoglyph={scores['homoglyph']:.0f})")
    return score, risk_level_for(score), reason
