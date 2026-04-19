"""
rule_engine.py — WATCH_LOGS SIEM Rule Engine
Evaluates threshold and match rules against Elasticsearch.
Returns a list of FiredAlert objects to be stored in-memory by app.py.
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)


# ── Data Model ────────────────────────────────────────────────────────────────

@dataclass
class FiredAlert:
    id: str
    rule_id: str
    rule_name: str
    description: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_name: str
    pattern: str
    matched_group: str          # value of the group_by field (e.g. IP address)
    matched_count: int          # how many events triggered the rule
    time_window_seconds: int
    timestamp: str              # ISO-8601 UTC
    type: str = "rule"          # "rule" | "correlation"
    raw_hits: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# ── Rule Engine ───────────────────────────────────────────────────────────────

class RuleEngine:
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = []
        self._load_rules()

    def _load_rules(self):
        try:
            with open(self.rules_path, "r") as f:
                self.rules = json.load(f)
            enabled = [r for r in self.rules if r.get("enabled", True)]
            logger.info(f"[RuleEngine] Loaded {len(enabled)} enabled rules from {self.rules_path}")
        except Exception as e:
            logger.error(f"[RuleEngine] Failed to load rules: {e}")
            self.rules = []

    def reload_rules(self):
        """Hot-reload rules from disk without restarting Flask."""
        self._load_rules()

    def evaluate_all_rules(self, es) -> list:
        """
        Evaluate all enabled rules against Elasticsearch.
        Returns a flat list of FiredAlert objects.
        """
        fired = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            try:
                if rule["type"] == "threshold":
                    alerts = self._evaluate_threshold(rule, es)
                elif rule["type"] == "match":
                    alerts = self._evaluate_match(rule, es)
                else:
                    logger.warning(f"[RuleEngine] Unknown rule type: {rule['type']}")
                    alerts = []
                fired.extend(alerts)
            except Exception as e:
                logger.error(f"[RuleEngine] Error evaluating rule '{rule.get('id')}': {e}")
        logger.info(f"[RuleEngine] Evaluation complete — {len(fired)} alert(s) fired")
        return fired

    # ── Threshold Rule ────────────────────────────────────────────────────────

    def _evaluate_threshold(self, rule: dict, es) -> list:
        """
        Fires if the number of matching events in the time window
        exceeds rule['threshold'], grouped by rule['group_by'].
        """
        window_ms = rule["time_window_seconds"] * 1000
        pattern = rule["pattern"]
        index = rule.get("index", "siem-logs-*")
        group_by = rule.get("group_by", "host.ip")
        threshold = rule.get("threshold", 5)

        # Build a regex OR pattern for multi-pattern rules
        patterns = [p.strip() for p in pattern.split("|")]
        should_clauses = [
            {"match_phrase": {rule.get("field", "message"): p}} for p in patterns
        ]

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{rule['time_window_seconds']}s", "lt": "now"}}},
                        {"bool": {"should": should_clauses, "minimum_should_match": 1}}
                    ]
                }
            },
            "aggs": {
                "by_group": {
                    "terms": {
                        "field": group_by if group_by.endswith(".keyword") else f"{group_by}.keyword",
                        "size": 50,
                        "min_doc_count": threshold
                    }
                }
            }
        }

        try:
            resp = es.search(index=index, body=query)
        except Exception as e:
            logger.error(f"[RuleEngine] ES query failed for rule {rule['id']}: {e}")
            return []

        alerts = []
        buckets = resp.get("aggregations", {}).get("by_group", {}).get("buckets", [])
        for bucket in buckets:
            count = bucket["doc_count"]
            group_val = bucket["key"]
            if count >= threshold:
                alert = FiredAlert(
                    id=str(uuid.uuid4()),
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    description=rule["description"],
                    severity=rule["severity"],
                    mitre_tactic=rule.get("mitre_tactic", ""),
                    mitre_technique=rule.get("mitre_technique", ""),
                    mitre_technique_name=rule.get("mitre_technique_name", ""),
                    pattern=pattern,
                    matched_group=str(group_val),
                    matched_count=count,
                    time_window_seconds=rule["time_window_seconds"],
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    type="rule"
                )
                alerts.append(alert)
        return alerts

    # ── Match Rule ────────────────────────────────────────────────────────────

    def _evaluate_match(self, rule: dict, es) -> list:
        """
        Fires once per unique group_by value where the pattern appears
        at least once in the time window.
        """
        pattern = rule["pattern"]
        index = rule.get("index", "siem-logs-*")
        group_by = rule.get("group_by", "host.ip")

        # Support |-delimited OR patterns
        patterns = [p.strip() for p in pattern.split("|")]
        should_clauses = [
            {"match_phrase": {rule.get("field", "message"): p}} for p in patterns
        ]

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": f"now-{rule['time_window_seconds']}s", "lt": "now"}}},
                        {"bool": {"should": should_clauses, "minimum_should_match": 1}}
                    ]
                }
            },
            "aggs": {
                "by_group": {
                    "terms": {
                        "field": group_by if group_by.endswith(".keyword") else f"{group_by}.keyword",
                        "size": 50,
                        "min_doc_count": 1
                    }
                }
            }
        }

        try:
            resp = es.search(index=index, body=query)
        except Exception as e:
            logger.error(f"[RuleEngine] ES query failed for rule {rule['id']}: {e}")
            return []

        alerts = []
        buckets = resp.get("aggregations", {}).get("by_group", {}).get("buckets", [])
        for bucket in buckets:
            count = bucket["doc_count"]
            group_val = bucket["key"]
            alert = FiredAlert(
                id=str(uuid.uuid4()),
                rule_id=rule["id"],
                rule_name=rule["name"],
                description=rule["description"],
                severity=rule["severity"],
                mitre_tactic=rule.get("mitre_tactic", ""),
                mitre_technique=rule.get("mitre_technique", ""),
                mitre_technique_name=rule.get("mitre_technique_name", ""),
                pattern=pattern,
                matched_group=str(group_val),
                matched_count=count,
                time_window_seconds=rule["time_window_seconds"],
                timestamp=datetime.now(timezone.utc).isoformat(),
                type="rule"
            )
            alerts.append(alert)
        return alerts

    def get_rules(self) -> list:
        """Returns the raw rule definitions (for the /api/rules endpoint)."""
        return [r for r in self.rules if r.get("enabled", True)]
