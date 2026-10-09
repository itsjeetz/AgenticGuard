import sqlite3
import json
import hashlib
from typing import Any, List, Optional
from pathlib import Path
from datetime import datetime, timezone

class EvalStore:
    def __init__(self, db_path: str = "data/eval_store.sqlite"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS eval_results (
                    item_id TEXT,
                    content_hash TEXT,
                    expected_labels TEXT,
                    carrier TEXT,
                    mode TEXT,
                    per_layer_scores TEXT,
                    final_verdict TEXT,
                    categories TEXT,
                    provider TEXT,
                    model TEXT,
                    latency REAL,
                    tokens INTEGER,
                    timestamp TEXT,
                    pipeline_fingerprint TEXT,
                    PRIMARY KEY (item_id, pipeline_fingerprint)
                )
            """)
            conn.commit()

    def save_result(self, result: dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO eval_results 
                (item_id, content_hash, expected_labels, carrier, mode, per_layer_scores, final_verdict, categories, provider, model, latency, tokens, timestamp, pipeline_fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.get("item_id"),
                result.get("content_hash"),
                json.dumps(result.get("expected_labels", [])),
                result.get("carrier"),
                result.get("mode"),
                json.dumps(result.get("per_layer_scores", {})),
                result.get("final_verdict"),
                json.dumps(result.get("categories", [])),
                result.get("provider"),
                result.get("model"),
                result.get("latency", 0.0),
                result.get("tokens", 0),
                result.get("timestamp", datetime.now(timezone.utc).isoformat()),
                result.get("pipeline_fingerprint")
            ))
            conn.commit()
            
    def save_results_batch(self, results: List[dict]):
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany("""
                INSERT OR REPLACE INTO eval_results 
                (item_id, content_hash, expected_labels, carrier, mode, per_layer_scores, final_verdict, categories, provider, model, latency, tokens, timestamp, pipeline_fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [(
                r.get("item_id"),
                r.get("content_hash"),
                json.dumps(r.get("expected_labels", [])),
                r.get("carrier"),
                r.get("mode"),
                json.dumps(r.get("per_layer_scores", {})),
                r.get("final_verdict"),
                json.dumps(r.get("categories", [])),
                r.get("provider"),
                r.get("model"),
                r.get("latency", 0.0),
                r.get("tokens", 0),
                r.get("timestamp", datetime.now(timezone.utc).isoformat()),
                r.get("pipeline_fingerprint")
            ) for r in results])
            conn.commit()

    def get_results_by_fingerprint(self, fingerprint: str) -> List[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM eval_results WHERE pipeline_fingerprint = ?", (fingerprint,))
            rows = cursor.fetchall()
            
            results = []
            for row in rows:
                d = dict(row)
                d["expected_labels"] = json.loads(d["expected_labels"])
                d["per_layer_scores"] = json.loads(d["per_layer_scores"])
                d["categories"] = json.loads(d["categories"])
                results.append(d)
            return results
            
    def get_all_fingerprints(self) -> List[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT DISTINCT pipeline_fingerprint FROM eval_results")
            return [row[0] for row in cursor.fetchall()]

def compute_pipeline_fingerprint(mode: str, code_version: str = "1.0", judge_prompt: str = "", fusion_config: str = "", model_name: str = "") -> str:
    """Compute the pipeline fingerprint based on mode and active config."""
    hasher = hashlib.sha256()
    hasher.update(mode.encode('utf-8'))
    hasher.update(code_version.encode('utf-8'))
    hasher.update(judge_prompt.encode('utf-8'))
    hasher.update(fusion_config.encode('utf-8'))
    hasher.update(model_name.encode('utf-8'))
    return hasher.hexdigest()
