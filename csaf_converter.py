#!/usr/bin/env python3

# Convert a CSAF document to OSV format
# i.e. https://access.redhat.com/security/data/csaf/v2/advisories/2024/rhsa-2024_4546.json

import argparse
import json

from rhel_osv.csaf import CSAF
from rhel_osv.osv import OSV, OSVEncoder


def main():
    parser = argparse.ArgumentParser(description='CSAF to OSV Converter')
    parser.add_argument("csaf", metavar="FILE", help='CSAF file to process')
    parser.add_argument('--output_directory', dest='out_dir', default="osv")

    args = parser.parse_args()

    print(f"Parsing {args.csaf}")
    csaf = CSAF(args.csaf)
    print(f"Advisory {csaf.id} affects products: {set(csaf.cpes.values())}")
    print(f"CVEs: {[v.cve_id for v in csaf.vulnerabilities]}")
    print(f"References:")
    for r in csaf.references:
        print(f"    {r.url}")

    osv = OSV(csaf)

    output_filename = f"{osv.id}.json"
    if args.out_dir:
        output_filename = f"{args.out_dir}/{output_filename}"
    with open(output_filename, 'w', encoding='utf-8') as out_f:
        json.dump(osv, out_f, cls=OSVEncoder, indent=2)

    print(f"\nConverted to OSV: {output_filename}")
    print("Related:")
    for r in osv.related:
        print(f"    {r}")
    print("Affected:")
    for affect in osv.affected:
        print(f"    {affect.package.ecosystem} {affect.package.purl}")
    print("References:")
    for ref in osv.references:
        print(f"    {ref.url} - {ref.type}")

if __name__ == '__main__':
    main()