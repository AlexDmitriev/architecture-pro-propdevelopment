#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlsplit


THREAT_BY_INCIDENT = {
    "secret_access": "high",
    "privileged_pod": "critical",
    "exec_foreign_pod": "high",
    "cluster_admin_rolebinding": "critical",
    "audit_policy_delete": "critical",
}

SUMMARY_BY_INCIDENT = {
    "secret_access": "Попытка доступа к secret под чужим service account",
    "privileged_pod": "Создание привилегированного pod",
    "exec_foreign_pod": "kubectl exec в чужой pod",
    "cluster_admin_rolebinding": "Создание RoleBinding с cluster-admin",
    "audit_policy_delete": "Удаление audit-policy.yaml",
}


def _deep_get(d: Dict[str, Any], path: str) -> Optional[Any]:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _resource_name(object_ref: Dict[str, Any]) -> str:
    resource = object_ref.get("resource") or ""
    subresource = object_ref.get("subresource")
    return f"{resource}/{subresource}" if resource and subresource else resource


def _exec_command(request_uri: Optional[str]) -> list[str]:
    if not request_uri:
        return []
    query = parse_qs(urlsplit(request_uri).query, keep_blank_values=True)
    return query.get("command", [])


def _has_privileged_container(request_object: Dict[str, Any]) -> bool:
    spec = request_object.get("spec") or {}
    containers = spec.get("containers") or []
    for container in containers:
        security_context = container.get("securityContext") or {}
        if security_context.get("privileged") is True:
            return True
    return False


def _is_kubectl_event(evt: Dict[str, Any]) -> bool:
    user_agent = evt.get("userAgent") or ""
    return user_agent.startswith("kubectl/")


def _effective_user(evt: Dict[str, Any]) -> Dict[str, Any]:
    return evt.get("impersonatedUser") or evt.get("user") or {}


def _event_key(incident: str, evt: Dict[str, Any], match: Dict[str, Any]) -> tuple[str, str, str, str, str]:
    object_ref = evt.get("objectRef") or {}
    name = object_ref.get("name") or match["details"].get("name") or ""
    namespace = object_ref.get("namespace") or match["details"].get("namespace") or ""
    user = _effective_user(evt).get("username") or ""
    return (incident, user, namespace, name, evt.get("verb") or "")


def classify_event(evt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if evt.get("kind") != "Event":
        return None
    if evt.get("stage") != "ResponseComplete":
        return None
    if not _is_kubectl_event(evt):
        return None

    object_ref = evt.get("objectRef") or {}
    request_object = evt.get("requestObject") or {}
    resource = object_ref.get("resource")
    subresource = object_ref.get("subresource")
    verb = evt.get("verb")
    namespace = object_ref.get("namespace")
    name = object_ref.get("name")
    effective_user = _effective_user(evt).get("username")
    commands = _exec_command(evt.get("requestURI"))

    if (
        resource == "secrets"
        and verb in {"get", "list"}
        and effective_user == "system:serviceaccount:secure-ops:monitoring"
    ):
        return {
            "incident": "secret_access",
            "details": {
                "access_as": effective_user,
                "target_namespace": namespace,
                "target_name": name,
            },
        }

    if (
        resource == "pods"
        and subresource is None
        and verb == "create"
        and name == "privileged-pod"
        and _has_privileged_container(request_object)
    ):
        return {
            "incident": "privileged_pod",
            "details": {
                "namespace": namespace,
                "name": name,
                "privileged": True,
            },
        }

    if resource == "pods" and subresource == "exec" and verb in {"get", "create", "connect"}:
        if namespace == "kube-system":
            return {
                "incident": "exec_foreign_pod",
                "details": {
                    "namespace": namespace,
                    "name": name,
                    "command": " ".join(commands),
                },
            }

    role_ref = request_object.get("roleRef") or {}
    if (
        resource == "rolebindings"
        and verb == "create"
        and role_ref.get("kind") == "ClusterRole"
        and role_ref.get("name") == "cluster-admin"
    ):
        return {
            "incident": "cluster_admin_rolebinding",
            "details": {
                "namespace": namespace,
                "name": name,
                "roleRef": role_ref,
            },
        }

    if (
        resource == "policies"
        and verb == "delete"
        and object_ref.get("apiGroup") == "audit.k8s.io"
        and (name == "audit-policy" or name == "audit-policy.yaml")
    ):
        return {
            "incident": "audit_policy_delete",
            "details": {
                "namespace": namespace,
                "name": name or "audit-policy.yaml",
            },
        }

    return None


def simplify_event(evt: Dict[str, Any], match: Dict[str, Any]) -> Dict[str, Any]:
    object_ref = evt.get("objectRef") or {}
    incident = match["incident"]
    user = _effective_user(evt)
    response_status = evt.get("responseStatus") or {}

    return {
        "incident": incident,
        "summary": SUMMARY_BY_INCIDENT[incident],
        "threat": THREAT_BY_INCIDENT[incident],
        "user.username": user.get("username"),
        "stage": evt.get("stage"),
        "verb": evt.get("verb"),
        "resource": _resource_name(object_ref),
        "namespace": object_ref.get("namespace"),
        "name": object_ref.get("name"),
        "status.code": (evt.get("responseStatus") or {}).get("code"),
        "message": response_status.get("message"),
        "details": match["details"],
    }


def main() -> int:
    p = argparse.ArgumentParser(description="audit.log -> JSONL только с нужными подозрительными событиями")
    p.add_argument("--in", dest="inp", default="audit.log", help="входной файл (по умолчанию audit.log)")
    p.add_argument("--out", dest="out", default="audit-extract.json", help="выходной JSONL (по умолчанию audit-extract.json)")
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
    matched = 0
    seen: set[tuple[str, str, str, str, str]] = set()

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

                match = classify_event(evt)
                if match:
                    key = _event_key(match["incident"], evt, match)
                    if key not in seen:
                        simple = simplify_event(evt, match)
                        f_out.write(json.dumps(simple, ensure_ascii=False) + "\n")
                        seen.add(key)
                        matched += 1

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
                print(
                    f"[progress] line={line_no} processed={processed} matched={matched} parse_errors={parse_errors}",
                    file=sys.stderr,
                )

    print(f"done: processed={processed} matched={matched} parse_errors={parse_errors} out={args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

