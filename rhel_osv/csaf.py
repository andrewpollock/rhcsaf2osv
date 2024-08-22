# Copyright (c) 2024 Jason Shepherd
# License: GPLv3+
"""Red Hat CSAF parser"""
import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterable

logger = logging.Logger(__name__)


class Remediation:
    """
    class to handle remediation advice in CSAF data
    """

    # pylint: disable=too-few-public-methods
    # This class is used for initialization and encapsulation of Remediation data

    def __init__(self, csaf_product_id: str, cpes: dict[str, str],
                 purls: dict[str, str]):
        if ":" not in csaf_product_id:
            raise ValueError(
                f"Did not find ':' in product_id: {csaf_product_id}")
        (self.product,
         self.product_version) = csaf_product_id.split(":", maxsplit=1)
        self.cpe = cpes.get(self.product)
        self.purl = purls.get(self.product_version)
        # There are many pkg:oci/ remediations in Red Hat data. However there are no strict
        # rules enforced on versioning Red Hat containers, therefore we cant compare container
        # versions to each other with 100% accuracy at this time.
        if not self.purl.startswith("pkg:rpm/"):
            raise ValueError(
                "Non RPM remediations are not supported in OSV at this time")

        # NEVRA stands for Name Epoch Version Release and Architecture
        # We split the name from the rest of the 'version' data (EVRA). We store name as component.
        split_component_version = self.product_version.rsplit("-", maxsplit=2)
        if len(split_component_version) != 3:
            raise ValueError(
                f"Could not convert component into NEVRA: {self.product_version}"
            )
        self.component = split_component_version[0]
        self.fixed_version = "-".join(
            (split_component_version[1], split_component_version[2]))


class Vulnerability:
    """
    class to handle vulnerability information
    """

    # pylint: disable=too-few-public-methods
    # This class encapsulates Red Hat CSAF Vulnerability data
    # Only initialization is required because data retrieval is via JSON encoding

    def __init__(self, csaf_vuln: dict[str, Any], cpes: dict[str, str],
                 purls: dict[str, str]):
        self.cve_id = csaf_vuln["cve"]
        for score in csaf_vuln["scores"]:
            if "cvss_v3" in score:
                self.cvss_v3_vector = score["cvss_v3"]["vectorString"]
                self.cvss_v3_base_score = score["cvss_v3"]["baseScore"]
        self.references = csaf_vuln["references"]
        self.remediations = []
        for product_id in csaf_vuln["product_status"]["fixed"]:
            try:
                self.remediations.append(Remediation(product_id, cpes, purls))
            except ValueError as e:
                logger.warning("Could not parse product_id: %s. %s",
                               product_id, e)


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
                yield from gen_dict_extract(key, v)
            elif isinstance(v, list):
                for d in v:
                    yield from gen_dict_extract(key, d)


def build_product_maps(
        product_tree_branches: dict) -> tuple[dict[str, str], dict[str, str]]:
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


class CSAF:
    """
    class to handle CSAF data read from a local file path
    """

    def __init__(self, csaf_file: str):
        file_path = Path(csaf_file)
        if not file_path.exists():
            print(f"Missing CSAF file: {csaf_file}.")
            sys.exit(1)

        with open(csaf_file, "r", encoding="utf-8") as fp:
            csaf_data = json.load(fp)

        if not csaf_data:
            print(f"Unable to load CSAF data from {csaf_file}.")
            sys.exit(1)

        self.doc = csaf_data["document"]

        self.csaf = {
            "type": self.doc["category"],
            "csaf_version": self.doc["csaf_version"]
        }

        # Only support csaf_vex 2.0
        if self.csaf != {"type": "csaf_vex", "csaf_version": "2.0"}:
            print(
                f"Sorry, I can only handle csaf_vex 2.0 documents, this one is {self.csaf}"
            )
            sys.exit(1)

        file_extension = file_path.suffix
        self.id = file_path.name.removesuffix(file_extension)

        self.cpes, self.purls = build_product_maps(csaf_data['product_tree'])

        self.vulnerabilities = [
            Vulnerability(v, self.cpes, self.purls)
            for v in (csaf_data["vulnerabilities"])
        ]

    @property
    def title(self):
        """
        Document Title
        """
        return self.doc["title"]

    @property
    def references(self):
        """
        Document References
        """
        return self.doc["references"]
