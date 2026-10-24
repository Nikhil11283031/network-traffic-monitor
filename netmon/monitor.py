"""The Monitor ties one running session together: the analyser and its optional parts (threat intelligence,
GeoIP, machine learning), the alert history database, notifications, the responder and the AI analyst.

The dashboard talks to a Monitor. Uploading a capture file in the browser starts a new session with the same
settings, so it can be analysed without restarting anything.
"""

from __future__ import annotations

import threading
import time

from .agent import SecurityAnalystAgent
from .analyzer import Analyzer, Config
from .responder import Responder


class Monitor:
    def __init__(self, source: str, config: Config | None = None, intel=None, geo=None, ml_learn: float | None = 40,
                 store=None, notifier=None, analyzer: Analyzer | None = None, agent=None, privacy_extra=None,
                 live: bool = False):
        self.config = config or (analyzer.config if analyzer else Config())
        self.intel, self.geo, self.ml_learn = intel, geo, ml_learn
        self.privacy_extra = privacy_extra or {}
        self.live = live
        self.self_test: dict | None = None
        self.store, self.notifier = store, notifier
        self.lock = threading.Lock()
        self.session = None
        self.new_session(source, analyzer=analyzer, agent=agent)

    def _make_analyzer(self) -> Analyzer:
        ml = None
        if self.ml_learn:
            from .ml import AnomalyDetector

            ml = AnomalyDetector(learn_seconds=self.ml_learn)
        from .privacy import PrivacyTracker

        return Analyzer(self.config, intel=self.intel, ml=ml, geo=self.geo,
                        privacy=PrivacyTracker(self.geo, self.privacy_extra))

    def new_session(self, source: str, analyzer: Analyzer | None = None, agent=None) -> Analyzer:
        analyzer = analyzer or self._make_analyzer()
        session = self.store.start_session(source) if self.store else None
        if self.store:
            analyzer.listeners.append(lambda alert, s=session: self.store.add(alert, s))
        if self.notifier:
            analyzer.listeners.append(self.notifier)
        responder = Responder()
        if agent is None:
            agent = SecurityAnalystAgent(analyzer, responder=responder)
        else:
            agent.toolbox.responder = responder
        with self.lock:
            self.analyzer, self.agent, self.responder = analyzer, agent, responder
            self.source, self.session = source, session
            self.busy = False
        return analyzer

    def analyze_file(self, path: str, name: str) -> threading.Thread:
        """Start a new session for an uploaded capture file and analyse it in the background."""
        from .capture import read_pcap

        analyzer = self.new_session(f"upload: {name}")
        self.busy = True

        def work():
            try:
                read_pcap(analyzer, path)
            except Exception as exc:
                self.upload_error = f"{type(exc).__name__}: {exc}"
            finally:
                self.busy = False

        self.upload_error = None
        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        return thread

    # ------------------------------------------------------------------ self-test and attack story

    def run_self_test(self, raise_alert: bool = False) -> dict:
        """Run the detection drills with the current settings (see selftest.py)."""
        from .selftest import run_drills

        result = run_drills(self.analyzer.config, self.intel)
        self.self_test = result
        if raise_alert and not result["ok"]:
            failed = [r for r in result["results"] if not r["ok"]]
            analyzer = self.analyzer
            with analyzer.lock:
                analyzer._alert([], analyzer.last_ts or result["ts"], "medium", "Self-test", "netmon", "detectors",
                                f"Self-test: {len(failed)} of {result['total']} drills were not detected - "
                                + "; ".join(f"{r['drill']}: {r['fix']}" for r in failed))
        return result

    def schedule_self_tests(self, every: float = 6 * 3600, stop_event=None) -> threading.Thread:
        """Live mode: run the self-test now and then every few hours in the background."""
        def loop():
            while True:
                try:
                    self.run_self_test(raise_alert=True)
                except Exception as exc:  # a self-test problem must never stop monitoring
                    self.self_test = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "results": []}
                if stop_event is not None:
                    if stop_event.wait(every):
                        return
                else:
                    time.sleep(every)

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        return thread

    def health(self) -> dict:
        from .selftest import capture_health

        return {"self_test": self.self_test, "capture": capture_health(self.analyzer, self.live)}

    def story(self) -> dict:
        from .story import build

        analyzer = self.analyzer
        mac_to_ip = {mac: ip for ip, mac in analyzer.ip_mac.items()}
        return build(analyzer.snapshot()["alerts"], mac_to_ip, analyzer.gateway())

    def acknowledge(self, alert_id: str, note: str = "", acked: bool = True) -> bool:
        found = self.analyzer.acknowledge(alert_id, note, acked) is not None
        if self.store:
            found = self.store.acknowledge(alert_id, note, acked) or found
        return found

    def status(self) -> dict:
        return {"source": self.source, "session": self.session, "busy": getattr(self, "busy", False),
                "upload_error": getattr(self, "upload_error", None),
                "agent": self.agent.label, "agent_mode": self.agent.mode,
                "history": self.store.stats() if self.store else None,
                "self_test": ({"passed": self.self_test.get("passed"), "total": self.self_test.get("total"),
                               "ok": self.self_test.get("ok")} if self.self_test else None),
                "notifications": self.notifier.status() if self.notifier else None}
