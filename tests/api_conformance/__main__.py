"""Conformance checker: call a running kernel and validate against the spec.

The spec file is supplied by path (``--spec`` or ``IM_OPENAPI_SPEC``) and is
never committed to the repository.
"""

import argparse
import base64
import json
import os
import re
import socket
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request

from .openapi_validate import resolve_ref, validate_with_warnings

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options")

LOGIN_PATH = "/login"
MQTT_DEFAULT = "127.0.0.1:1883"
HTTP_TIMEOUT_S = 10


# --------------------------------------------------------------------------
# spec handling

def load_spec(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def resolve_param(spec, param):
    if isinstance(param, dict) and "$ref" in param:
        return resolve_ref(spec, param["$ref"])
    return param


def path_template_params(template):
    return re.findall(r"\{([^}/]+)\}", template)


def iter_operations(spec):
    """Yield one dict per operation: method, path, tag, operation, params."""
    ops = []
    for template, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for raw_method, operation in path_item.items():
            if raw_method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            method = raw_method.upper()
            tags = operation.get("tags") or []
            params = [resolve_param(spec, p)
                      for p in (operation.get("parameters") or [])]
            ops.append({
                "method": method,
                "path": template,
                "tag": tags[0] if tags else "",
                "tags": tags,
                "operation": operation,
                "params": params,
            })
    ops.sort(key=lambda o: (o["path"], o["method"]))
    return ops


def response_schema(spec, operation, status):
    """Return the response schema dict (or None) for an HTTP status."""
    responses = operation.get("responses") or {}
    key = str(status)
    entry = responses.get(key)
    if entry is None:
        for name, candidate in responses.items():
            if (len(name) == 3 and name[1:] == "XX"
                    and name[0] == key[0]):
                entry = candidate
                break
    if entry is None and "default" in responses:
        entry = responses["default"]
    if not isinstance(entry, dict):
        return None, False
    content = entry.get("content") or {}
    media = content.get("application/json")
    if isinstance(media, dict) and isinstance(media.get("schema"), dict):
        return media["schema"], True
    return None, "content" not in entry


def documented_statuses(operation):
    out = set()
    for name in (operation.get("responses") or {}):
        out.add(str(name))
    return out


def status_documented(operation, status):
    key = str(status)
    responses = operation.get("responses") or {}
    if key in responses or "default" in responses:
        return True
    return any(len(n) == 3 and n[1:] == "XX" and n[0] == key[0]
               for n in responses)


# --------------------------------------------------------------------------
# http

def http_call(method, url, headers, body=None):
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method.upper())
    for name, value in headers.items():
        req.add_header(name, value)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def api_json(method, base, path, headers, query=None, body=None):
    url = base.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query, doseq=True)
    status, raw = http_call(method, url, headers, body)
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else None
    except (ValueError, UnicodeDecodeError):
        parsed = None
    return status, parsed, raw


# --------------------------------------------------------------------------
# cases

def load_cases(cases_dir):
    cases = {}
    if not cases_dir or not os.path.isdir(cases_dir):
        return cases
    for name in sorted(os.listdir(cases_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(cases_dir, name), "r", encoding="utf-8") as fh:
            try:
                items = json.load(fh)
            except ValueError:
                continue
        if isinstance(items, dict):
            items = [items]
        for case in items:
            if isinstance(case, dict) and case.get("operation"):
                cases.setdefault(str(case["operation"]), []).append(case)
    return cases


def walk_pointer(data, pointer):
    node = data
    if not pointer or pointer == "/":
        return node
    for raw in pointer.lstrip("#").lstrip("/").split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            node = node[int(token)]
        elif isinstance(node, dict):
            node = node[token]
        else:
            raise KeyError("cannot walk %r" % pointer)
    return node


def mqtt_connect(host, port, clientid, username=None, password=None, keepalive=60):
    """Open a minimal MQTT 3.1.1 CONNECT and keep the socket open."""
    cid = clientid.encode("utf-8")
    user = username.encode("utf-8") if username else None
    pwd = password.encode("utf-8") if password else None
    flags = 0x02
    if user is not None:
        flags |= 0x80
    if pwd is not None:
        flags |= 0x40
    payload = struct.pack("!H", len(cid)) + cid
    if user is not None:
        payload += struct.pack("!H", len(user)) + user
    if pwd is not None:
        payload += struct.pack("!H", len(pwd)) + pwd
    var_hdr = (struct.pack("!H", 4) + b"MQTT" + bytes([4, flags])
               + struct.pack("!H", keepalive))
    rest = var_hdr + payload
    fixed = b"\x10" + _mqtt_len(len(rest))
    sock = socket.create_connection((host, port), timeout=HTTP_TIMEOUT_S)
    try:
        sock.settimeout(HTTP_TIMEOUT_S)
        sock.sendall(fixed + rest)
        ack = sock.recv(4)
        if len(ack) < 4 or ack[0] != 0x20 or ack[3] != 0x00:
            raise ConnectionError("CONNACK failed: %r" % ack)
    except Exception:
        sock.close()
        raise
    return sock


def _mqtt_len(n):
    out = bytearray()
    while True:
        digit = n % 128
        n //= 128
        if n:
            digit |= 0x80
        out.append(digit)
        if not n:
            return bytes(out)


def _mqtt_recv_packet(sock):
    """Read one MQTT control packet from an edge socket."""
    header = sock.recv(1)
    if len(header) < 1:
        raise ConnectionError("MQTT recv failed: empty header")
    length = 0
    shift = 0
    while True:
        digit = sock.recv(1)
        if len(digit) < 1:
            raise ConnectionError("MQTT recv failed: truncated length")
        byte = digit[0]
        length |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
        if shift >= 28:
            raise ConnectionError("MQTT recv failed: bad length")
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise ConnectionError("MQTT recv failed: truncated body")
        body += chunk
    return header + body


def mqtt_subscribe_over(sock, packet_id, topic, qos=0):
    """Send a normal authorized SUBSCRIBE over an open edge socket.

    Blocks for the SUBACK so the kernel has recorded the subscribe
    authorization decision before the management read runs. Any granted
    or denied code is accepted; only a missing SUBACK fails.
    """
    encoded = topic.encode("utf-8")
    body = (struct.pack("!H", packet_id) + struct.pack("!H", len(encoded))
            + encoded + bytes([qos & 0xFF]))
    sock.sendall(b"\x82" + _mqtt_len(len(body)) + body)
    pkt = _mqtt_recv_packet(sock)
    if (pkt[0] >> 4) != 9:
        raise ConnectionError("SUBACK failed: %r" % pkt)


def mqtt_publish_over(sock, topic, qos=0, payload=b"", packet_id=1):
    """Send a normal authorized PUBLISH over an open edge socket.

    QoS 0 returns after the send; QoS 1 blocks for the PUBACK so the
    kernel has recorded the publish authorization decision first.
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    encoded = topic.encode("utf-8")
    body = struct.pack("!H", len(encoded)) + encoded
    if qos > 0:
        body += struct.pack("!H", packet_id)
    body += bytes(payload)
    sock.sendall(bytes([0x30 | ((qos & 0x03) << 1)])
                 + _mqtt_len(len(body)) + body)
    if qos == 1:
        pkt = _mqtt_recv_packet(sock)
        if (pkt[0] >> 4) != 4:
            raise ConnectionError("PUBACK failed: %r" % pkt)


class CaseRunner:
    def __init__(self, base, headers, mqtt_host, mqtt_port):
        self.base = base
        self.headers = headers
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.sockets = {}

    def _resolve_value(self, value):
        if isinstance(value, str) and value.startswith("$from:"):
            ref = value[len("$from:"):]
            op_part, _, pointer = ref.partition("#")
            method, _, src_path = op_part.strip().partition(" ")
            status, parsed, _ = api_json(method.strip() or "GET",
                                         self.base, src_path.strip(),
                                         self.headers)
            if status < 200 or status >= 300:
                raise KeyError("source %s returned status %d" % (op_part, status))
            return walk_pointer(parsed, "#" + pointer)
        return value

    def _run_step(self, step):
        if not isinstance(step, dict) or len(step) != 1:
            raise ValueError("bad step: %r" % (step,))
        kind, args = next(iter(step.items()))
        args = args if isinstance(args, dict) else {}
        if kind == "api":
            api_json(args.get("method", "GET"), self.base,
                     args.get("path", "/"), self.headers,
                     body=args.get("body"))
        elif kind == "mqtt_connect":
            sock = mqtt_connect(self.mqtt_host, self.mqtt_port,
                                args.get("clientid", "conf-c1"),
                                args.get("username"), args.get("password"),
                                args.get("keepalive", 60))
            self.sockets[args.get("clientid", "conf-c1")] = sock
        elif kind == "mqtt_disconnect":
            sock = self.sockets.pop(args.get("clientid", ""), None)
            if sock is not None:
                sock.close()
        elif kind == "mqtt_subscribe":
            sock = self.sockets.get(args.get("clientid", "conf-c1"))
            if sock is None:
                raise ValueError("mqtt_subscribe without mqtt_connect: %r" % (args,))
            mqtt_subscribe_over(sock, int(args.get("packet_id", 7)),
                                str(args.get("topic", "")),
                                int(args.get("qos", 0)))
        elif kind == "mqtt_publish":
            sock = self.sockets.get(args.get("clientid", "conf-c1"))
            if sock is None:
                raise ValueError("mqtt_publish without mqtt_connect: %r" % (args,))
            mqtt_publish_over(sock, str(args.get("topic", "")),
                              int(args.get("qos", 0)),
                              args.get("payload", b""),
                              int(args.get("packet_id", 1)))
        else:
            raise ValueError("unknown step type: %s" % kind)

    def run_setup(self, case):
        for step in case.get("setup") or []:
            self._run_step(step)

    def run_cleanup(self, case):
        for step in case.get("cleanup") or []:
            try:
                if (isinstance(step, dict) and "mqtt_connect" in step
                        and len(step) == 1):
                    cid = (step["mqtt_connect"] or {}).get("clientid", "conf-c1")
                    sock = self.sockets.pop(cid, None)
                    if sock is not None:
                        sock.close()
                else:
                    self._run_step(step)
            except Exception:
                pass
        for cid in [c for c in self.sockets
                    if c == (case.get("path_params") or {}).get("clientid")]:
            try:
                self.sockets.pop(cid).close()
            except Exception:
                pass

    def close_all(self):
        for sock in self.sockets.values():
            try:
                sock.close()
            except Exception:
                pass
        self.sockets.clear()


# --------------------------------------------------------------------------
# checking

def substitute_path(template, path_params):
    def repl(match):
        name = match.group(1)
        return urllib.parse.quote(str(path_params[name]), safe="")
    return re.sub(r"\{([^}/]+)\}", repl, template)


def check_meta(body, query, errors):
    if not isinstance(body, dict):
        return
    meta = body.get("meta")
    if not isinstance(meta, dict) or "data" not in body:
        return
    for field in ("page", "limit", "count"):
        if field not in meta:
            errors.append("/meta: missing %r" % field)
    if not isinstance(meta.get("page"), int):
        errors.append("/meta/page: expected integer")
    elif "page" in (query or {}) and meta["page"] != int(query["page"]):
        errors.append("/meta/page: expected %r, got %r"
                      % (int(query["page"]), meta["page"]))
    if not isinstance(meta.get("limit"), int):
        errors.append("/meta/limit: expected integer")
    elif "limit" in (query or {}) and meta["limit"] != int(query["limit"]):
        errors.append("/meta/limit: expected %r, got %r"
                      % (int(query["limit"]), meta["limit"]))
    if "count" in meta and not isinstance(meta["count"], int):
        errors.append("/meta/count: expected integer")


def plan_operations(ops, only, exclude_tags):
    excluded = {t.strip() for t in (exclude_tags or "").split(",") if t.strip()}
    matcher = re.compile(only) if only else None
    planned = []
    for op in ops:
        if excluded and any(t in excluded for t in op["tags"]):
            continue
        label = "%s %s" % (op["method"], op["path"])
        if matcher and not matcher.search(label):
            continue
        planned.append(op)
    return planned


def decide(op, cases, allow_mutations):
    """Return (action, case, reason) without touching the network."""
    key = "%s %s" % (op["method"], op["path"])
    names = path_template_params(op["path"])
    case = (cases.get(key) or [None])[0]
    if names and (case is None or not all(
            n in (case.get("path_params") or {}) for n in names)):
        return "skip", None, "skipped:needs-case"
    if op["method"] == "GET":
        return "call", case, ""
    if case is None or not allow_mutations:
        if case is None:
            return "skip", None, "skipped:needs-case"
        return "skip", case, "skipped:needs-allow-mutations"
    return "call", case, ""


def check_one(spec, op, case, runner, authed, api_json_fn=None):
    key = "%s %s" % (op["method"], op["path"])
    query = dict((case or {}).get("query") or {})
    body = (case or {}).get("body")
    call_json = api_json_fn or api_json
    try:
        params = {n: runner._resolve_value(v) for n, v
                  in ((case or {}).get("path_params") or {}).items()}
    except Exception as exc:
        return {"method": op["method"], "path": op["path"], "tag": op["tag"],
                "outcome": "skipped:case-error", "status": None,
                "errors": [str(exc)], "warnings": []}
    target = substitute_path(op["path"], params)
    try:
        if case is not None:
            runner.run_setup(case)
        status, parsed, raw = call_json(op["method"], runner.base, target,
                                        runner.headers, query or None, body)
    except Exception as exc:
        return {"method": op["method"], "path": op["path"], "tag": op["tag"],
                "outcome": "fail", "status": None, "errors": [str(exc)],
                "warnings": []}
    finally:
        if case is not None:
            runner.run_cleanup(case)

    errors = []
    warnings = []
    if status in (401, 403) and authed:
        return {"method": op["method"], "path": op["path"], "tag": op["tag"],
                "outcome": "auth-error", "status": status,
                "errors": ["unauthorized with admin credentials"],
                "warnings": []}
    if status in (404, 405) and _empty_or_non_json(parsed, raw):
        return {"method": op["method"], "path": op["path"], "tag": op["tag"],
                "outcome": "not-implemented", "status": status, "errors": [],
                "warnings": []}
    if status in (404, 405) and not status_documented(op["operation"], status):
        return {"method": op["method"], "path": op["path"], "tag": op["tag"],
                "outcome": "not-implemented", "status": status, "errors": [],
                "warnings": []}
    if not status_documented(op["operation"], status):
        errors.append("status %d not documented" % status)
    else:
        schema, _ = response_schema(spec, op["operation"], status)
        if schema is not None:
            if parsed is None and raw:
                errors.append("/: expected JSON body, got non-JSON")
            elif parsed is None and not raw:
                errors.append("/: expected JSON body, got empty body")
            else:
                verrs, wwarns = validate_with_warnings(schema, parsed, spec)
                errors += verrs
                warnings += wwarns
            if isinstance(parsed, dict):
                check_meta(parsed, query, errors)
    if case is not None and case.get("expect_status") is not None:
        if status != case["expect_status"]:
            errors.append("expected status %r, got %r"
                          % (case["expect_status"], status))
    return {"method": op["method"], "path": op["path"], "tag": op["tag"],
            "outcome": "pass" if not errors else "fail",
            "status": status, "errors": errors, "warnings": warnings}


def _empty_or_non_json(parsed, raw):
    """True when a 404/405 body carries no JSON verdict to judge."""
    if not raw:
        return True
    if parsed is not None:
        return False
    if isinstance(raw, (bytes, bytearray)) and bytes(raw).strip() == b"null":
        return False
    if isinstance(raw, str) and raw.strip() == "null":
        return False
    return True


# --------------------------------------------------------------------------
# cli

def build_parser():
    ap = argparse.ArgumentParser(
        description="Validate a running IndraMQTT kernel against the API spec.")
    ap.add_argument("--spec", default=os.environ.get("IM_OPENAPI_SPEC"),
                    help="path to openapi.json (or env IM_OPENAPI_SPEC)")
    ap.add_argument("--base", default="http://127.0.0.1:18083/api/v5",
                    help="kernel base URL including /api/v5")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default=None)
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--api-secret", default=None)
    ap.add_argument("--only", default=None,
                    help='regex on "METHOD path"')
    ap.add_argument("--cases", default="tests/api_conformance/cases")
    ap.add_argument("--allow-mutations", action="store_true")
    ap.add_argument("--report", default=None)
    ap.add_argument("--list", action="store_true",
                    help="print what would be called; no network")
    ap.add_argument("--exclude-tags", default="",
                    help='comma list, e.g. "Plugins,AI Completion,A2A Registry"')
    ap.add_argument("--mqtt", default=MQTT_DEFAULT,
                    help="mqtt host:port for mqtt_connect steps")
    return ap


def do_login(base, args):
    headers = {}
    if args.api_key:
        token = base64.b64encode(
            ("%s:%s" % (args.api_key, args.api_secret or "")).encode()
        ).decode()
        headers["Authorization"] = "Basic " + token
        return headers, True
    if args.password is None:
        return headers, False
    status, parsed, _ = api_json("POST", base, LOGIN_PATH, {},
                                 body={"username": args.user,
                                       "password": args.password})
    if status != 200 or not isinstance(parsed, dict) or not parsed.get("token"):
        if isinstance(parsed, dict) and parsed.get("must_change_password"):
            sys.exit("login refused: must_change_password is true; "
                     "change the password first")
        sys.exit("login failed with status %d" % status)
    if parsed.get("must_change_password"):
        sys.exit("login refused: must_change_password is true; "
                 "change the password first")
    headers["Authorization"] = "Bearer " + parsed["token"]
    return headers, True


def print_summary(rows):
    by_tag = {}
    for row in rows:
        slot = by_tag.setdefault(row["tag"] or "(untagged)", {})
        slot[row["outcome"]] = slot.get(row["outcome"], 0) + 1
    width = max([len(t) for t in by_tag] + [3])
    print("%-*s  pass  fail  not-impl  auth-err  skipped" % (width, "tag"))
    for tag in sorted(by_tag):
        s = by_tag[tag]
        skipped = sum(n for o, n in s.items() if o.startswith("skipped"))
        print("%-*s  %-4d  %-4d  %-8d  %-8d  %d" % (
            width, tag, s.get("pass", 0), s.get("fail", 0),
            s.get("not-implemented", 0), s.get("auth-error", 0), skipped))
    total = len(rows)
    passed = sum(1 for r in rows if r["outcome"] == "pass")
    print("total %d, pass %d" % (total, passed))


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.spec:
        sys.exit("need --spec <openapi.json> or IM_OPENAPI_SPEC")
    spec = load_spec(args.spec)
    ops = iter_operations(spec)
    total = len(ops)
    planned = plan_operations(ops, args.only, args.exclude_tags)
    cases = load_cases(args.cases)

    if args.list:
        rows = []
        for op in planned:
            action, _, reason = decide(op, cases, args.allow_mutations)
            if action == "call":
                print("CALL %s %s" % (op["method"], op["path"]))
                rows.append({"method": op["method"], "path": op["path"],
                             "tag": op["tag"], "outcome": "would-call",
                             "status": None, "errors": [], "warnings": []})
            else:
                print("SKIP %s %s: %s" % (op["method"], op["path"], reason))
                rows.append({"method": op["method"], "path": op["path"],
                             "tag": op["tag"], "outcome": reason,
                             "status": None, "errors": [], "warnings": []})
        tagged = plan_operations(ops, None, args.exclude_tags)
        print("operations: %d (excluded %d, candidates %d)"
              % (total, total - len(tagged), len(planned)))
        if args.report:
            with open(args.report, "w", encoding="utf-8") as fh:
                json.dump(rows, fh, indent=2)
        return 0

    headers, authed = do_login(args.base, args)
    host, _, port = args.mqtt.rpartition(":")
    runner = CaseRunner(args.base, headers, host or "127.0.0.1", int(port or 1883))
    rows = []
    try:
        for op in planned:
            action, case, reason = decide(op, cases, args.allow_mutations)
            if action == "skip":
                rows.append({"method": op["method"], "path": op["path"],
                             "tag": op["tag"], "outcome": reason,
                             "status": None, "errors": [], "warnings": []})
                continue
            rows.append(check_one(spec, op, case, runner, authed))
    finally:
        runner.close_all()
    print_summary(rows)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
    failed = [r for r in rows if r["outcome"] in ("fail", "auth-error")]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
