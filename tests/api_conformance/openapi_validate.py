"""Minimal OpenAPI 3.0 response-schema validator (standard library only).

Supports the subset used by the conformance checker: local ``$ref``,
``type``/``nullable``, ``properties``/``required``/``additionalProperties``,
``items``, ``enum``, ``oneOf``/``anyOf``/``allOf``, ``minimum``/``maximum``,
``minLength``/``maxLength`` and ``format: date-time`` (loose check).

``validate`` returns a list of ``"<json-pointer>: <message>"`` strings;
an empty list means the data is valid.
"""

import re

_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?([Zz]|[+-]\d{2}:?\d{2})?$"
)

_MAX_DEPTH = 50


def _escape(token):
    return str(token).replace("~", "~0").replace("/", "~1")


def _child(pointer, token):
    token = _escape(token)
    if pointer in ("", "/"):
        return "/" + token
    return pointer + "/" + token


def _type_name(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def resolve_ref(spec, ref):
    """Resolve a local ``#/a/b`` reference against the loaded spec."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise ValueError("only local refs supported: %r" % (ref,))
    node = spec
    for raw in ref[2:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or token not in node:
            raise KeyError("unresolvable $ref: %s" % ref)
        node = node[token]
    return node


def validate(schema, data, spec=None, path=""):
    """Validate ``data`` against ``schema``; return a list of errors."""
    errors, _ = validate_with_warnings(schema, data, spec, path)
    return errors


def validate_with_warnings(schema, data, spec=None, path=""):
    """Validate ``data``; return ``(errors, warnings)``.

    ``oneOf`` branches that overlap can match more than one branch: that
    is accepted but reported as a warning, never as an error.
    """
    errors = []
    warnings = []
    _check(schema, data, spec or {}, path or "/", errors, 0, (), warnings)
    return errors, warnings


def _check(schema, data, spec, pointer, errors, depth, seen, warnings=None):
    if warnings is None:
        warnings = []
    if depth > _MAX_DEPTH:
        errors.append("%s: schema too deep (possible cycle)" % pointer)
        return
    if not isinstance(schema, dict):
        return

    if "$ref" in schema:
        ref = schema["$ref"]
        try:
            target = resolve_ref(spec, ref)
        except (ValueError, KeyError) as exc:
            errors.append("%s: %s" % (pointer, exc))
            return
        if ref in seen:
            return
        seen = seen + (ref,)
        _check(target, data, spec, pointer, errors, depth + 1, seen, warnings)
        for key, value in schema.items():
            if key == "$ref":
                continue
            _check({key: value}, data, spec, pointer, errors, depth + 1, seen,
                   warnings)
        return

    if data is None:
        if schema.get("nullable") is True:
            return
        if "enum" in schema and None in schema["enum"]:
            return
        if ("type" not in schema and "properties" not in schema
                and "items" not in schema and "enum" not in schema):
            return
        errors.append("%s: expected %s, got null"
                      % (pointer, schema.get("type", "non-null")))
        return

    if "enum" in schema:
        try:
            if data not in schema["enum"]:
                errors.append("%s: %r not in enum %r"
                              % (pointer, data, schema["enum"]))
                return
        except TypeError:
            errors.append("%s: cannot compare against enum" % pointer)
            return

    if "allOf" in schema:
        subs = schema["allOf"] or []
        for sub in subs:
            _check(sub, data, spec, pointer, errors, depth + 1, seen, warnings)

    if "oneOf" in schema:
        subs = schema["oneOf"] or []
        valid = sum(1 for sub in subs if _silent(sub, data, spec, seen))
        if valid == 0:
            errors.append("%s: expected one of %d oneOf schemas"
                          % (pointer, len(subs)))
            return
        if valid > 1:
            warnings.append(
                "%s: matched %d of %d oneOf schemas"
                % (pointer, valid, len(subs)))

    if "anyOf" in schema:
        subs = schema["anyOf"] or []
        if not any(_silent(sub, data, spec, seen) for sub in subs):
            errors.append("%s: expected one of %d anyOf schemas"
                          % (pointer, len(subs)))
            return

    declared = schema.get("type")
    if declared is not None:
        names = declared if isinstance(declared, list) else [declared]
        if not any(_matches_type(n, data) for n in names):
            errors.append("%s: expected %s, got %s"
                          % (pointer, "/".join(names), _type_name(data)))
            return

    if isinstance(data, str):
        _check_string(schema, data, pointer, errors)
    elif isinstance(data, bool):
        pass
    elif isinstance(data, (int, float)):
        _check_number(schema, data, pointer, errors)
    elif isinstance(data, list):
        _check_array(schema, data, spec, pointer, errors, depth, seen, warnings)
    elif isinstance(data, dict):
        _check_object(schema, data, spec, pointer, errors, depth, seen, warnings)


def _silent(schema, data, spec, seen):
    probe = []
    _check(schema, data, spec, "/", probe, 0, seen, [])
    return not probe


def _matches_type(name, data):
    if name == "string":
        return isinstance(data, str)
    if name == "integer":
        return isinstance(data, int) and not isinstance(data, bool)
    if name == "number":
        return isinstance(data, (int, float)) and not isinstance(data, bool)
    if name == "boolean":
        return isinstance(data, bool)
    if name == "array":
        return isinstance(data, list)
    if name == "object":
        return isinstance(data, dict)
    return True


def _check_string(schema, data, pointer, errors):
    min_len = schema.get("minLength")
    if isinstance(min_len, int) and len(data) < min_len:
        errors.append("%s: string shorter than minLength %d"
                      % (pointer, min_len))
    max_len = schema.get("maxLength")
    if isinstance(max_len, int) and len(data) > max_len:
        errors.append("%s: string longer than maxLength %d"
                      % (pointer, max_len))
    if schema.get("format") == "date-time":
        if not _DATETIME_RE.match(data):
            errors.append("%s: expected date-time, got %r" % (pointer, data))


def _check_number(schema, data, pointer, errors):
    minimum = schema.get("minimum")
    if isinstance(minimum, (int, float)) and not isinstance(minimum, bool):
        if data < minimum:
            errors.append("%s: %r less than minimum %r"
                          % (pointer, data, minimum))
    maximum = schema.get("maximum")
    if isinstance(maximum, (int, float)) and not isinstance(maximum, bool):
        if data > maximum:
            errors.append("%s: %r greater than maximum %r"
                          % (pointer, data, maximum))


def _check_array(schema, data, spec, pointer, errors, depth, seen, warnings):
    items = schema.get("items")
    if isinstance(items, dict):
        for i, entry in enumerate(data):
            _check(items, entry, spec, _child(pointer, i),
                   errors, depth + 1, seen, warnings)


def _check_object(schema, data, spec, pointer, errors, depth, seen, warnings):
    required = schema.get("required") or []
    for name in required:
        if name not in data:
            errors.append("%s: missing required property %r" % (pointer, name))
    properties = schema.get("properties") or {}
    for name, sub in properties.items():
        if name in data:
            _check(sub, data[name], spec, _child(pointer, name),
                   errors, depth + 1, seen, warnings)
    if "additionalProperties" in schema:
        extra = schema["additionalProperties"]
        for name, value in data.items():
            if name in properties:
                continue
            if extra is False:
                errors.append("%s: unexpected property %r" % (pointer, name))
            elif isinstance(extra, dict):
                _check(extra, value, spec, _child(pointer, name),
                       errors, depth + 1, seen, warnings)
