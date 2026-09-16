"""Unit tests for openapi_validate (inline schemas only)."""

import unittest

from . import __main__ as checker
from .openapi_validate import resolve_ref, validate, validate_with_warnings

SPEC = {
    "components": {
        "schemas": {
            "Name": {"type": "string", "minLength": 2},
            "User": {
                "type": "object",
                "required": ["name"],
                "properties": {"name": {"$ref": "#/components/schemas/Name"}},
            },
        }
    }
}


class ValidateTest(unittest.TestCase):
    def assert_ok(self, schema, data, spec=None):
        self.assertEqual(validate(schema, data, spec or {}), [])

    def assert_bad(self, schema, data, spec=None):
        self.assertTrue(validate(schema, data, spec or {}))

    # $ref
    def test_ref_pass(self):
        self.assert_ok({"$ref": "#/components/schemas/User"},
                       {"name": "ann"}, SPEC)

    def test_ref_fail(self):
        self.assert_bad({"$ref": "#/components/schemas/User"},
                        {"name": "x"}, SPEC)

    # type
    def test_type_object_pass(self):
        self.assert_ok({"type": "object"}, {})

    def test_type_object_fail(self):
        self.assert_bad({"type": "object"}, [])

    def test_type_array_pass(self):
        self.assert_ok({"type": "array"}, [1])

    def test_type_array_fail(self):
        self.assert_bad({"type": "array"}, {})

    def test_type_string_pass(self):
        self.assert_ok({"type": "string"}, "a")

    def test_type_string_fail(self):
        self.assert_bad({"type": "string"}, 3)

    def test_type_integer_pass(self):
        self.assert_ok({"type": "integer"}, 3)

    def test_type_integer_fail_bool(self):
        self.assert_bad({"type": "integer"}, True)

    def test_type_integer_fail(self):
        self.assert_bad({"type": "integer"}, 3.5)

    def test_type_number_pass(self):
        self.assert_ok({"type": "number"}, 3.5)

    def test_type_number_fail(self):
        self.assert_bad({"type": "number"}, "x")

    def test_type_boolean_pass(self):
        self.assert_ok({"type": "boolean"}, False)

    def test_type_boolean_fail(self):
        self.assert_bad({"type": "boolean"}, 0)

    # nullable / null
    def test_nullable_pass(self):
        self.assert_ok({"type": "string", "nullable": True}, None)

    def test_nullable_fail(self):
        self.assert_bad({"type": "string"}, None)

    def test_null_untyped_pass(self):
        self.assert_ok({}, None)

    def test_null_description_only_pass(self):
        self.assert_ok({"description": "anything"}, None)

    def test_null_typed_fail(self):
        self.assert_bad({"type": "string"}, None)

    def test_null_nullable_typed_pass(self):
        self.assert_ok({"type": "string", "nullable": True}, None)

    def test_null_enum_with_null_pass(self):
        self.assert_ok({"enum": ["a", None]}, None)

    def test_null_enum_without_null_fail(self):
        self.assert_bad({"enum": ["a", "b"]}, None)

    # properties
    def test_properties_pass(self):
        self.assert_ok({"properties": {"a": {"type": "string"}}}, {"a": "x"})

    def test_properties_fail(self):
        errors = validate({"properties": {"a": {"type": "string"}}}, {"a": 1})
        self.assertTrue(errors and errors[0].startswith("/a:"))

    # required
    def test_required_pass(self):
        self.assert_ok({"required": ["a"]}, {"a": 1})

    def test_required_fail(self):
        self.assert_bad({"required": ["a"]}, {})

    # additionalProperties
    def test_additional_false_pass(self):
        self.assert_ok({"properties": {"a": {}},
                        "additionalProperties": False}, {"a": 1})

    def test_additional_false_fail(self):
        self.assert_bad({"properties": {"a": {}},
                         "additionalProperties": False}, {"b": 1})

    def test_additional_schema_pass(self):
        self.assert_ok({"additionalProperties": {"type": "string"}}, {"b": "x"})

    def test_additional_schema_fail(self):
        self.assert_bad({"additionalProperties": {"type": "string"}}, {"b": 1})

    # items
    def test_items_pass(self):
        self.assert_ok({"items": {"type": "integer"}}, [1, 2])

    def test_items_fail_pointer(self):
        errors = validate({"items": {"type": "integer"}}, [1, "x"])
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("/1:"))

    # enum
    def test_enum_pass(self):
        self.assert_ok({"enum": ["a", "b"]}, "a")

    def test_enum_fail(self):
        self.assert_bad({"enum": ["a", "b"]}, "c")

    # oneOf
    def test_oneof_pass(self):
        self.assert_ok({"oneOf": [{"type": "string"}, {"type": "integer"}]}, 4)

    def test_oneof_fail_none(self):
        self.assert_bad({"oneOf": [{"type": "string"}, {"type": "integer"}]},
                        4.5)

    def test_oneof_fail_both_warns(self):
        errors, warnings = validate_with_warnings(
            {"oneOf": [{"type": "number"}, {"type": "integer"}]}, 4)
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)

    def test_oneof_overlap_single_branch_no_warning(self):
        errors, warnings = validate_with_warnings(
            {"oneOf": [{"type": "string"}, {"type": "integer"}]}, 4)
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])

    # anyOf
    def test_anyof_pass(self):
        self.assert_ok({"anyOf": [{"type": "string"}, {"type": "integer"}]}, 4)

    def test_anyof_fail(self):
        self.assert_bad({"anyOf": [{"type": "string"}, {"type": "integer"}]},
                        4.5)

    # allOf
    def test_allof_pass(self):
        self.assert_ok({"allOf": [{"type": "integer"}, {"minimum": 2}]}, 4)

    def test_allof_fail(self):
        self.assert_bad({"allOf": [{"type": "integer"}, {"minimum": 5}]}, 4)

    # minimum / maximum
    def test_minimum_pass(self):
        self.assert_ok({"minimum": 2}, 2)

    def test_minimum_fail(self):
        self.assert_bad({"minimum": 2}, 1)

    def test_maximum_pass(self):
        self.assert_ok({"maximum": 5}, 5)

    def test_maximum_fail(self):
        self.assert_bad({"maximum": 5}, 6)

    # minLength / maxLength
    def test_minlength_pass(self):
        self.assert_ok({"minLength": 2}, "ab")

    def test_minlength_fail(self):
        self.assert_bad({"minLength": 2}, "a")

    def test_maxlength_pass(self):
        self.assert_ok({"maxLength": 2}, "ab")

    def test_maxlength_fail(self):
        self.assert_bad({"maxLength": 2}, "abc")

    # format date-time
    def test_datetime_pass(self):
        self.assert_ok({"format": "date-time"}, "2024-01-01T12:34:56.789+08:00")

    def test_datetime_fail(self):
        self.assert_bad({"format": "date-time"}, "not a date")

    def test_other_format_ignored(self):
        self.assert_ok({"format": "password"}, "anything")

    def test_resolve_ref_missing(self):
        with self.assertRaises(KeyError):
            resolve_ref(SPEC, "#/components/schemas/Nope")


class DecideTest(unittest.TestCase):
    def test_get_with_path_params_needs_no_mutations(self):
        op = {"method": "GET", "path": "/clients/{clientid}",
              "tag": "Clients", "operation": {}, "params": []}
        cases = {"GET /clients/{clientid}":
                 [{"operation": "GET /clients/{clientid}",
                   "path_params": {"clientid": "c1"}}]}
        action, case, _ = checker.decide(op, cases, False)
        self.assertEqual(action, "call")
        self.assertIsNotNone(case)

    def test_delete_with_path_params_needs_allow_mutations(self):
        op = {"method": "DELETE", "path": "/clients/{clientid}",
              "tag": "Clients", "operation": {}, "params": []}
        cases = {"DELETE /clients/{clientid}":
                 [{"operation": "DELETE /clients/{clientid}",
                   "path_params": {"clientid": "c1"}}]}
        action, _, reason = checker.decide(op, cases, False)
        self.assertEqual(action, "skip")
        self.assertEqual(reason, "skipped:needs-allow-mutations")


class CheckOneTest(unittest.TestCase):
    def test_missing_route_empty_body_is_not_implemented(self):
        op = {"method": "GET", "path": "/clients/{clientid}",
              "tag": "Clients",
              "operation": {"responses": {
                  "200": {"description": "ok"},
                  "404": {"description": "not found"}}}}
        case = {"operation": "GET /clients/{clientid}",
                "path_params": {"clientid": "c1"}}

        class StubRunner:
            base = "http://127.0.0.1:1/api/v5"
            headers = {}

            def _resolve_value(self, value):
                return value

            def run_setup(self, _case):
                pass

            def run_cleanup(self, _case):
                pass

        def stub_api_json(method, base, path, headers, query=None, body=None):
            return 404, None, b""

        row = checker.check_one({}, op, case, StubRunner(), False,
                                api_json_fn=stub_api_json)
        self.assertEqual(row["outcome"], "not-implemented")
        self.assertEqual(row["status"], 404)


if __name__ == "__main__":
    unittest.main()
