#!/usr/bin/env python3

# Convert a CSAF document to OSV format
# i.e. https://access.redhat.com/security/data/csaf/v2/advisories/2024/rhsa-2024_4546.json

import argparse

from rhel_osv.csaf import CSAF


def main():
    parser = argparse.ArgumentParser(description='CSAF to OSV Converter')
    parser.add_argument("csaf", metavar="FILE", help='CSAF file to process')

    args = parser.parse_args()

    print(f"Parsing {args.csaf}")
    csaf = CSAF(args.csaf)
    print(f"Advisory {csaf.id} affects products: {set(csaf.cpes.values())}")
    print(f"CVEs: {[v.cve_id for v in csaf.vulnerabilities]}")
    print(f"References:")
    for r in csaf.references:
        print(f"    {r.url}")

if __name__ == '__main__':
    main()