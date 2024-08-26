#!/usr/bin/env python3

# Convert a CSAF document to OSV format
# i.e. https://access.redhat.com/security/data/csaf/v2/advisories/2024/rhsa-2024_4546.json
"""
Command line utility for converting a single Red Hat CSAF document to OSV format
"""
import argparse
import json
import os
import sys

from jsonschema import validate
from jsonschema.exceptions import ValidationError

from rhel_osv.csaf import CSAF
from rhel_osv.osv import OSV, OSVEncoder

SCHEMA_PATH = f"schema-v{OSV.SCHEMA_VERSION}.json"


def main():
    """
    Given a Red Hat CSAF document, covert it to OSV. Writes the OSV file to disk at 'osv' by default
    """
    parser = argparse.ArgumentParser(description='CSAF to OSV Converter')
    parser.add_argument("csaf", metavar="FILE", help='CSAF file to process')
    parser.add_argument('--output_directory', dest='out_dir', default="osv")

    args = parser.parse_args()

    print(f"Parsing {args.csaf}")
    csaf = CSAF(args.csaf)
    print(f"Advisory {csaf.id} affects products: {set(csaf.cpes.values())}")
    print(f"CVEs: {[v.cve_id for v in csaf.vulnerabilities]}")
    print("References:")
    for r in csaf.references:
        print(f"    {r['url']}")

    osv = OSV(csaf)

    if not osv.affected:
        print("Didn't find any affects in OSV data, skipping.")
        sys.exit(0)

    output_filename = _write_and_validate_osv(args.out_dir, osv)

    if not output_filename:
        sys.exit(1)

    print(f"\nConverted to OSV: {output_filename}")
    print("Related:")
    for r in osv.related:
        print(f"    {r}")
    print("Affected:")
    for affect in osv.affected:
        print(f"    {affect.package.ecosystem} {affect.package.purl}")
    print("References:")
    for ref in osv.references:
        print(f"    {ref['url']} - {ref['type']}")


def _write_and_validate_osv(out_dir: str, osv: OSV):
    output_filename = f"{osv.id}.json"
    if out_dir:
        output_filename = f"{out_dir}/{output_filename}"

    with open(SCHEMA_PATH, 'r', encoding="utf-8") as schema_file:
        osv_schema = json.load(schema_file)

    with open(output_filename, 'w+', encoding='utf-8') as out_f:
        json.dump(osv, out_f, cls=OSVEncoder, indent=2)
        out_f.flush()
        out_f.seek(0)
        json_data = json.load(out_f)

    try:
        validate(json_data, schema=osv_schema)
    except ValidationError as e:
        print(f"Error: Got Validation Error for {output_filename}; {e}")
        os.remove(output_filename)
        return ""

    return output_filename


if __name__ == '__main__':
    main()
