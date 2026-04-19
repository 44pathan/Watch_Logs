"""
correlator.py — WATCH_LOGS SIEM Correlation Engine
Detects multi-step attack sequences by correlating events across a time window.
Each correlation rule defines an ordered sequence of patterns; if ALL steps
fire for the same host within the time window, a CorrelatedAlert is raised.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


# ── Data Model ────────────────────────────────────────────────────────────────

@dataclass
class CorrelatedAlert:
    id: str
    rule_id: str
    rule_name: str
    description: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_name: str
    matched_group: str          # e.g. hostname that triggered the sequence
    event_counts: list          # hit count per sequence step
    sequence: list              # sequence step definitions from the rule
    time_window_seconds: int
    timestamp: str              # ISO-8601 UTC when correlation fired
    type: str = "correlation"

    def to_dict(self):
        return asdict(self)


# ── Correlator ────────────────────────────────────────────────────────────────

class Correlator:
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = []
        self._load_rules()

    # ── Rule management ───────────────────────────────────────────────────────

    def _load_rules(self):
        try:
            with open(self.rules_path, "r") as f:
                all_rules = json.load(f)
            self.rules = [r for r in all_rules if r.get("enabled", True)]
            logger.info(
                f"[Correlator] Loaded {len(self.rules)} correlation rule(s) "
                f"from {self.rules_path}"
            )
        except Exception as e:
            logger.error(f"[Correlator] Failed to load rules: {e}")
            self.rules = []

    def reload_rules(self):
        """Hot-reload correlation rules without restarting Flask."""
        self._load_rules()

    def get_rules(self) -> list:
        return self.rules

    # ── Query helpers ─────────────────────────────────────────────────────────

    def _build_pattern_query(self, pattern: str, field: str = "message") -> dict:
        """
        Build a bool.should query from a |-delimited pattern string.
        Each segment is matched as a phrase against the target field.
        """
        parts = [p.strip() for p in pattern.split("|") if p.strip()]
        if len(parts) == 1:
            return {"match_phrase": {field: parts[0]}}
        return {
            "bool": {
                "should": [{"match_phrase": {field: p}} for p in parts],
                "minimum_should_match": 1,
            }
        }

    def _keyword_field(self, field: str) -> str:
        """Ensure an ES field name ends with .keyword for aggregations."""
        return field if field.endswith(".keyword") else f"{field}.keyword"

    # ── Core evaluation ───────────────────────────────────────────────────────

    def evaluate_all_rules(self, es) -> list:
        """
        Evaluate all enabled correlation rules against Elasticsearch.
        Returns a flat list of CorrelatedAlert objects.
        """
        fired = []
        for rule in self.rules:
            try:
                alerts = self._evaluate_sequence_rule(rule, es)
                if alerts:
                    logger.info(
                        f"[Correlator] Rule '{rule['id']}' fired "
                        f"{len(alerts)} correlated alert(s)"
                    )
                fired.extend(alerts)
            except Exception as e:
                logger.error(
                    f"[Correlator] Error evaluating rule '{rule.get('id')}': {e}"
                )
        logger.info(
            f"[Correlator] Evaluation complete — {len(fired)} correlated alert(s)"
        )
        return fired

    def _evaluate_sequence_rule(self, rule: dict, es) -> list:
        """
        For every step in the sequence, query ES for matching events within
        the time window grouped by the group_by field.

        A CorrelatedAlert fires for every host/group that satisfies ALL steps
        (i.e. appears in the result buckets for each step with count >= min_count).
        """
        index          = rule.get("index", "siem-logs-*")
        group_by       = rule.get("group_by", "host.hostname")
        time_window_s  = rule["time_window_seconds"]
        sequence       = rule.get("sequence", [])
        field          = rule.get("field", "message")
        now_iso        = datetime.now(timezone.utc).isoformat()

        if not sequence:
            logger.warning(f"[Correlator] Rule '{rule['id']}' has no sequence steps.")
            return []

        keyword_field = self._keyword_field(group_by)
        time_range    = f"now-{time_window_s}s"

        # Collect {group_value -> hit_count} for each step
        step_group_counts: list[dict] = []

        for step in sequence:
            pattern   = step["pattern"]
            min_count = step.get("min_count", 1)

            pattern_query = self._build_pattern_query(pattern, field)

            try:
                resp = es.search(index=index, body={
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": {"@timestamp": {
                                    "gte": time_range,
                                    "lt":  "now"
                                }}},
                                pattern_query
                            ]
                        }
                    },
                    "aggs": {
                        "by_group": {
                            "terms": {
                                "field":         keyword_field,
                                "size":          100,
                                "min_doc_count": min_count
                            }
                        }
                    }
                })
            except Exception as e:
                logger.error(
                    f"[Correlator] ES query failed for rule '{rule['id']}' "
                    f"step pattern '{pattern}': {e}"
                )
                return []   # abort this rule on ES error

            group_counts = {
                b["key"]: b["doc_count"]
                for b in resp.get("aggregations", {})
                                .get("by_group", {})
                                .get("buckets", [])
            }
            step_group_counts.append(group_counts)

        # ── Intersection: find groups that satisfied every sequence step ──────
        if not step_group_counts:
            return []

        common_groups = set(step_group_counts[0].keys())
        for sc in step_group_counts[1:]:
            common_groups &= set(sc.keys())

        fired = []
        for group in common_groups:
            counts = [sc.get(group, 0) for sc in step_group_counts]
            alert = CorrelatedAlert(
                id                   = str(uuid.uuid4()),
                rule_id              = rule["id"],
                rule_name            = rule["name"],
                description          = rule["description"],
                severity             = rule["severity"],
                mitre_tactic         = rule.get("mitre_tactic", ""),
                mitre_technique      = rule.get("mitre_technique", ""),
                mitre_technique_name = rule.get("mitre_technique_name", ""),
                matched_group        = str(group),
                event_counts         = counts,
                sequence             = sequence,
                time_window_seconds  = time_window_s,
                timestamp            = now_iso,
                type                 = "correlation"
            )
            fired.append(alert)

        return fired
