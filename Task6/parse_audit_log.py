#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional


def _deep_get(d: Dict[str, Any], path: str) -> Optional[Any]:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def simplify_event(evt: Dict[str, Any]) -> Dict[str, Any]:
    response_status = evt.get("responseStatus") or {}
    annotations = _deep_get(evt, "annotations") or {}
    decision = annotations.get("authorization.k8s.io/decision") if isinstance(annotations, dict) else None
    reason = annotations.get("authorization.k8s.io/reason") if isinstance(annotations, dict) else None

    simple: Dict[str, Any] = {
        "kind": evt.get("kind"),
        "level": evt.get("level"),
        "apiVersion": evt.get("apiVersion"),
        "auditID": evt.get("auditID"),
        "stage": evt.get("stage"),
        "requestURI": evt.get("requestURI"),
        "verb": evt.get("verb"),
        "requestReceivedTimestamp": evt.get("requestReceivedTimestamp"),
        "stageTimestamp": evt.get("stageTimestamp"),
        "decision": decision,
        "decisionReason": reason,
        "user": evt.get("user"),
        "sourceIPs": evt.get("sourceIPs"),
        "objectRef": evt.get("objectRef"),
        "userAgent": evt.get("userAgent"),
        "responseStatus": {
            "status": response_status.get("status"),
            "code": response_status.get("code"),
            "reason": response_status.get("reason"),
            "message": response_status.get("message"),
            "details": response_status.get("details"),
        },
    }

    if "responseObject" in evt:
        ro = evt.get("responseObject") or {}
        simple["responseObject"] = {
            "kind": ro.get("kind"),
            "apiVersion": ro.get("apiVersion"),
            "status": ro.get("status"),
            "code": ro.get("code"),
            "message": ro.get("message"),
            "metadata": ro.get("metadata"),
        }

    return simple

def is_security_alert(evt: Dict[str, Any], line: str) -> bool:
    if evt.get("verb") == "get" and evt.get("objectRef").get("resource") == "secrets":
        return True

    if evt.get("verb") == "create" and evt.get("objectRef").get("subresource") == "exec":
        return True    

    if evt.get("requestObject", {}).get("spec", {}).get("containers", [{}])[0].get("securityContext", {}).get("privileged") and evt.get("objectRef").get("resource") == "pods":
        return True    

    if "audit-policy" in line:
        return True    

    if "cluster-admin" in line:    
        return True    

    return False

def main() -> int:
    p = argparse.ArgumentParser(description="audit.log -> упрощенный JSONL построчно")
    p.add_argument("--in", dest="inp", default="audit.log", help="входной файл (по умолчанию audit.log)")
    p.add_argument("--out", dest="out", default="audit-extract.json", help="выходной JSONL (по умолчанию audit.parsed.jsonl)")
    p.add_argument("--limit", type=int, default=0, help="сколько строк обработать (0 = все)")
    p.add_argument(
        "--keep-raw-on-error",
        action="store_true",
        help="если строка не парсится как JSON, записать в out с полем _parse_error и raw",
    )
    p.add_argument("--progress-every", type=int, default=5000, help="выводить прогресс каждые N строк (0 = без прогресса)")
    args = p.parse_args()

    processed = 0
    parse_errors = 0

    with open(args.inp, "r", encoding="utf-8", errors="replace") as f_in, open(args.out, "w", encoding="utf-8") as f_out:
        for line_no, line in enumerate(f_in, start=1):
            if args.limit and processed >= args.limit:
                break

            line = line.strip()
            if not line:
                continue

            try:
                evt = json.loads(line)
                if not isinstance(evt, dict):
                    raise ValueError("json value is not an object")

                simple = simplify_event(evt)
                
                if is_security_alert(simple, line):
                    f_out.write(json.dumps(simple, ensure_ascii=False) + "\n")
                
                processed += 1
            except Exception as e:
                parse_errors += 1
                if args.keep_raw_on_error:
                    err_obj: Dict[str, Any] = {
                        "_parse_error": str(e),
                        "_line_no": line_no,
                        "raw": line[:20000],
                    }
                    f_out.write(json.dumps(err_obj, ensure_ascii=False) + "\n")

            if args.progress_every and line_no % args.progress_every == 0:
                print(f"[progress] line={line_no} processed={processed} parse_errors={parse_errors}", file=sys.stderr)

    print(f"done: processed={processed} parse_errors={parse_errors} out={args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

