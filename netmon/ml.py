"""Machine-learning anomaly detection with an Isolation Forest.

The rule-based detectors only catch what someone thought of in advance and only above fixed limits. This
detector instead *learns what normal looks like on your network* and flags behaviour that does not fit.

How it works:
1. Traffic is cut into short time windows (5 seconds). For every local device that was active in a window, a
   feature vector describes its behaviour: packets and bytes sent, how many different hosts and ports it
   contacted, connection attempts, DNS lookups, and how long and random its DNS names were.
2. Learning phase: for the first part of the capture (default 40 seconds; use several minutes for live traffic)
   these vectors are collected as examples of normal behaviour.
3. An Isolation Forest (scikit-learn) is trained on them. It builds many random decision trees; unusual points
   are isolated in fewer splits, which gives them a lower (more negative) anomaly score.
4. After that, each new window is scored (below 0 = anomalous, around 0.1 and above = clearly normal). A window
   is reported only if its score is below score_threshold (0.1, i.e. not confidently normal) AND at least one
   feature is at least double the highest value seen while learning. The second check makes every alert
   explainable ("contacted 20 different ports, normal is up to 2") and stops alarms for devices that are just
   quieter than usual - with little training data an Isolation Forest alone gives too many false positives.

Unsupervised: it needs no labelled attack data, which real networks rarely have.
"""

from __future__ import annotations

import math

from .analyzer import PacketInfo, is_local, shannon_entropy

FEATURES = [
    ("packets_out", "sent {v:,.0f} packets"),
    ("kb_out", "sent {v:,.0f} KB"),
    ("peers", "talked to {v:.0f} different hosts"),
    ("ports", "contacted {v:.0f} different ports"),
    ("conn_attempts", "made {v:.0f} connection attempts"),
    ("dns_queries", "made {v:.0f} DNS lookups"),
    ("dns_max_len", "looked up a name with a {v:.0f}-character label"),
    ("dns_max_entropy", "looked up a name with randomness {v:.1f}"),
]
NORMAL_UNIT = {"packets_out": "{v:,.0f}", "kb_out": "{v:,.0f} KB", "dns_max_entropy": "{v:.1f}"}


class AnomalyDetector:
    def __init__(self, window: float = 5.0, learn_seconds: float = 40.0, min_samples: int = 12,
                 score_threshold: float = 0.1, random_state: int = 927):
        self.window = window
        self.learn_seconds = learn_seconds
        self.min_samples = min_samples
        self.score_threshold = score_threshold
        self.random_state = random_state
        self.start: float | None = None
        self.bucket: int | None = None
        self.current: dict[str, dict] = {}
        self.training: list[list[float]] = []
        self.model = None
        self.normal_max: list[float] = []
        self.error: str | None = None
        self.scored = 0
        try:
            from sklearn.ensemble import IsolationForest  # noqa: F401
        except ImportError:
            self.error = "scikit-learn is not installed (pip install scikit-learn)"

    # ------------------------------------------------------------------ input

    def observe(self, p: PacketInfo) -> list[dict]:
        """Feed one packet. Returns anomalies found in windows that have just finished."""
        if self.error:
            return []
        if self.start is None:
            self.start = p.ts
        bucket = int((p.ts - self.start) // self.window)
        found = []
        if self.bucket is None:
            self.bucket = bucket
        elif bucket > self.bucket:  # only move forward: slightly out-of-order packets join the current window
            found = self._close_window()
            self.bucket = bucket
        elif bucket < self.bucket - 1:  # far out of order (a badly sorted file): leave it out of the ML features
            return found
        if is_local(p.src):
            f = self.current.setdefault(p.src, {"packets_out": 0, "bytes_out": 0, "peers": set(), "ports": set(),
                                                "conn_attempts": 0, "dns_queries": 0, "dns_max_len": 0,
                                                "dns_max_entropy": 0.0})
            f["packets_out"] += 1
            f["bytes_out"] += p.length
            f["peers"].add(p.dst)
            starts = (p.proto == "TCP" and "S" in p.flags and "A" not in p.flags) or p.proto in ("UDP", "DNS")
            if p.dport is not None and starts:
                f["ports"].add(p.dport)
                f["conn_attempts"] += 1
            if p.dns_query:
                f["dns_queries"] += 1
                label = max(p.dns_query.rstrip(".").split("."), key=len)
                f["dns_max_len"] = max(f["dns_max_len"], len(label))
                f["dns_max_entropy"] = max(f["dns_max_entropy"], shannon_entropy(label))
        return found

    def flush(self) -> list[dict]:
        """Score the last, unfinished window (call when a capture file ends)."""
        return self._close_window() if self.current and not self.error else []

    # ------------------------------------------------------------------ model

    @staticmethod
    def _vector(f: dict) -> list[float]:
        return [f["packets_out"], f["bytes_out"] / 1000, len(f["peers"]), len(f["ports"]), f["conn_attempts"],
                f["dns_queries"], f["dns_max_len"], f["dns_max_entropy"]]

    def _close_window(self) -> list[dict]:
        window_end = self.start + (self.bucket + 1) * self.window
        vectors = {host: self._vector(f) for host, f in self.current.items()}
        self.current = {}
        if self.model is None:
            learning = window_end <= self.start + self.learn_seconds or len(self.training) < self.min_samples
            if learning:
                self.training.extend(vectors.values())
                return []
            self._train()
        found = []
        if not vectors:
            return found
        hosts = list(vectors)
        scores = self.model.decision_function([self._log(vectors[h]) for h in hosts])  # one call per window
        for host, raw in zip(hosts, scores):
            self.scored += 1
            vec, score = vectors[host], float(raw)
            reasons = self._reasons(vec)
            if score < self.score_threshold and reasons:
                found.append({"host": host, "ts": window_end, "score": round(score, 3), "reasons": reasons,
                              "features": dict(zip([n for n, _ in FEATURES], vec))})
        return found

    @staticmethod
    def _log(vec):
        return [math.log1p(v) for v in vec]

    def _train(self):
        from sklearn.ensemble import IsolationForest

        self.model = IsolationForest(n_estimators=200, contamination="auto", random_state=self.random_state)
        self.model.fit([self._log(v) for v in self.training])
        self.normal_max = [max(v[i] for v in self.training) for i in range(len(FEATURES))]

    def _reasons(self, vec) -> list[str]:
        """Features clearly above anything seen while learning (at least double the normal maximum, with a
        small floor so tiny numbers do not count)."""
        floors = [20, 50, 5, 5, 10, 5, 25, 3.8]
        out = []
        for i, (name, text) in enumerate(FEATURES):
            normal = self.normal_max[i]
            if vec[i] >= max(2 * normal, floors[i]) and vec[i] > normal:
                unit = NORMAL_UNIT.get(name, "{v:.0f}")
                out.append(f"{text.format(v=vec[i])} (normal: up to {unit.format(v=normal)})")
        return out

    def status(self) -> dict:
        if self.error:
            return {"state": "unavailable", "reason": self.error}
        return {"state": "active" if self.model is not None else "learning",
                "learn_seconds": self.learn_seconds, "trained_on": len(self.training),
                "windows_scored": self.scored, "model": "Isolation Forest (scikit-learn)"}
