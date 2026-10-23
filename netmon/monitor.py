"""The Monitor ties one running session together: the analyser and its optional parts (threat intelligence,
GeoIP, machine learning), the alert history database, notifications, the responder and the AI analyst.

The dashboard talks to a Monitor. Uploading a capture file in the browser starts a new session with the same
settings, so it can be analysed without restarting anything.
"""

from __future__ import annotations

import threading

from .agent import SecurityAnalystAgent
from .analyzer import Analyzer, Config
from .responder import Responder


class Monitor:
    def __init__(self, source: str, config: Config | None = None, intel=None, geo=None, ml_learn: float | None = 40,
                 store=None, notifier=None, analyzer: Analyzer | None = None, agent=None):
        self.config = config or (analyzer.config if analyzer else Config())
        self.intel, self.geo, self.ml_learn = intel, geo, ml_learn
        self.store, self.notifier = store, notifier
        self.lock = threading.Lock()
        self.session = None
        self.new_session(source, analyzer=analyzer, agent=agent)

    def _make_analyzer(self) -> Analyzer:
        ml = None
        if self.ml_learn:
            from .ml import AnomalyDetector

            ml = AnomalyDetector(learn_seconds=self.ml_learn)
        return Analyzer(self.config, intel=self.intel, ml=ml, geo=self.geo)

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
                "notifications": self.notifier.status() if self.notifier else None}
