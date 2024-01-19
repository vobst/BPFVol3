#!/usr/bin/env python3

import json
import sys

from jsonschema import FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError
from jsonschema.validators import validate

CHECKER_ALL = FormatChecker(
    [
        "color",
        "duration",
        "date-time",
        "hostname",
        "idn-hostname",
        "date",
        "email",
        "ipv4",
        "ipv6",
        "iri",
        "iri-reference",
        "json-pointer",
        "regex",
        "relative-json-pointer",
        "time",
        "uri",
        "uri-reference",
        "uri-template",
    ]
)


def main():
    target = json.load(open(sys.argv[1]))
    schema = json.load(open(sys.argv[2]))
    try:
        print(f"Validating {target} against {schema}. This may take a while...")
        validate(target, schema, format_checker=CHECKER_ALL)
        print("OK")
    except SchemaError as e:
        print(f"Invalid schema: {e}")
    except ValidationError as e:
        print(f"Invalid format: {e}")


if __name__ == "__main__":
    main()
