# Copyright (c) 2024 Jason Shepherd
# License: GPLv3+

import json
from pathlib import Path
from typing import Any, Iterable



class Reference(object):
    """
    class to handle CSAF References
    """
    def __init__(self, csaf_ref: dict[str, str]):
        self.category = csaf_ref["category"]
        self.summary = csaf_ref["summary"]
        self.url = csaf_ref["url"]


class Remediation(object):
    """
    class to handle remediation advice in CSAF data
    """
    def __init__(self, csaf_product_id: str, cpes: dict[str, str], purls: dict[str, str]):
        if ":" not in csaf_product_id:
            raise ValueError(f"Did not find ':' in product_id: {csaf_product_id}")
        (self.product, self.product_version) = csaf_product_id.split(":", maxsplit=1)
        self.cpe = cpes.get(self.product)
        self.purl = purls.get(self.product_version)

        # NEVRA stands for Name Epoch Version Revision and Architecture
        # We split the name from the rest of the 'version' data (EVRA). We store name as component.
        split_component_version = self.product_version.rsplit("-", maxsplit=2)
        if len(split_component_version) != 3:
            raise ValueError(f"Could not convert component into NEVRA: {self.product_version}")
        self.component = split_component_version[0]
        self.fixed_version = "-".join((split_component_version[1], split_component_version[2]))


class Vulnerability(object):
    """
    class to handle vulnerability information
    """
    def __init__(self, csaf_vuln: dict[str, Any], cpes: dict[str, str], purls: dict[str, str]):
        self.cve_id = csaf_vuln["cve"]
        for score in csaf_vuln["scores"]:
            if "cvss_v3" in score:
                self.cvss_v3_vector = score["cvss_v3"]["vectorString"]
                self.cvss_v3_base_score = score["cvss_v3"]["baseScore"]
        self.remediations = []
        for product_id in csaf_vuln["product_status"]["fixed"]:
            try:
                self.remediations.append(Remediation(product_id, cpes, purls))
            except ValueError as e:
                print(f"Warning: Could not parse product_id: {product_id}: {e}")

def gen_dict_extract(key, var: Iterable):
    """
    Given a key value and dictionary or list, traverses that dictionary or list returning the value
    of the given key.
    From https://stackoverflow.com/questions/9807634/
        find-all-occurrences-of-a-key-in-nested-dictionaries-and-lists
    """
    if hasattr(var, "items"):
        for k, v in var.items():
            if k == key:
                yield v
            if isinstance(v, dict):
                for result in gen_dict_extract(key, v):
                    yield result
            elif isinstance(v, list):
                for d in v:
                    for result in gen_dict_extract(key, d):
                        yield result


def build_product_maps(product_tree_branches: dict) -> tuple[dict[str, str], dict[str, str]]:
    """
    Given a CSAF product tree branch dictionary returns a tuple of CPEs by product ID and PURLs by
    product ID.
    """
    cpe_map = {}
    purl_map = {}
    products = gen_dict_extract("product", product_tree_branches)
    for product in products:
        product_id = product["product_id"]
        if "product_identification_helper" in product:
            helper = product["product_identification_helper"]
            if "cpe" in helper:
                cpe_map[product_id] = helper["cpe"]
            elif "purl" in helper:
                purl_map[product_id] = helper["purl"]
    return cpe_map, purl_map


class CSAF(object):
    """
    class to handle CSAF data read from a local file path
    """
    def __init__(self, csaffile: str):
        file_path = Path(csaffile)
        if not file_path.exists():
            print(f"Missing CSAF file: {csaffile}.")
            exit(1)

        with open(csaffile) as fp:
            csafdata = json.load(fp)

        if not csafdata:
            print(f"Unable to load CSAF data from {csaffile}.")
            exit(1)

        self.doc = csafdata["document"]

        self.csaf = {"type": self.doc["category"], "csaf_version": self.doc["csaf_version"]}

        # Only support csaf_vex 2.0
        if self.csaf != {"type": "csaf_vex", "csaf_version": "2.0"}:
            print(f"Sorry, I can only handle csaf_vex 2.0 documents, this one is {self.csaf}")
            exit(1)

        self.title = self.doc["title"]

        self.references = [Reference(r) for r in self.doc["references"]]

        file_extension = file_path.suffix
        self.id = file_path.name.removesuffix(file_extension)

        self.cpes, self.purls = build_product_maps(csafdata['product_tree'])

        self.vulnerabilities = [
            Vulnerability(v, self.cpes, self.purls) for v in (csafdata["vulnerabilities"])
        ]
