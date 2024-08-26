# Copyright (c) 2024 Jason Shepherd
# License: GPLv3+
"""Red Hat CSAF parser to OSV converter."""
import datetime
import re
from json import JSONEncoder
from rhel_osv.csaf import Remediation, CSAF


class OSVEncoder(JSONEncoder):
    """ Encodes OSV objects into JSON format"""

    def default(self, o):
        if isinstance(o, Event):
            return o.encode_json()
        return o.__dict__


class Event:
    """
    Class to hold event information for a Range. Advisories for Red Hat RPM based products always
    assume all previous versions are affected.
    """
    # pylint: disable=too-few-public-methods
    # This class encapsulates and validates version range events
    # Only a single public method is required for custom JSON encoding

    INTRODUCED = "introduced"
    FIXED = "fixed"

    def __init__(self, event_type: str, version: str = "0"):
        expected = (self.INTRODUCED, self.FIXED)
        if event_type not in expected:
            raise ValueError(
                f"Expected one of {expected} for type. Got {event_type}")
        self.event_type = event_type
        self.version = version

    def encode_json(self):
        """
        Custom JSON encoding for event type which changes attribute name depending on the type of
        event eg. introduced or fixed
        """
        if self.event_type == Event.INTRODUCED:
            return {Event.INTRODUCED: self.version}
        if self.event_type == Event.FIXED:
            return {Event.FIXED: self.version}
        raise ValueError("Unexpected event_type for Event")


class Range:
    """
    Class to hold range information for a Package. Ecosystem here refers to RPM versions as defined
    in https://github.com/rpm-software-management/rpm/blob/master/rpmio/rpmvercmp.c
    """

    # pylint: disable=too-few-public-methods
    # This class encapsulates version range types as 'ECOSYSTEM' type
    # Only initialization is required because data retrieval is via JSON encoding

    def __init__(self, fixed: str):
        self.type = "ECOSYSTEM"
        self.events = [Event("introduced"), Event("fixed", fixed)]


class Package:
    """
    Class to hold package data for an Affect. Expects an ecosystem string that starts with
    CPE_PATTERN.
    Replaces the CPE prefix 'redhat' part with 'Red Hat' to match more closely with other ecosystem
    identifiers in the OSV database
    """
    # pylint: disable=too-few-public-methods
    # This class encapsulates Red Hat RPM Packages by Ecosystem
    # Only initialization is required because data retrieval is via JSON encoding

    CPE_PATTERN = re.compile(r"cpe:/[oa]:(redhat)")

    def __init__(self, name: str, ecosystem: str, purl: str):
        self.name = name
        if not self.CPE_PATTERN.match(ecosystem):
            raise ValueError(f"Got unsupported ecosystem: {ecosystem}")
        self.ecosystem = f"Red Hat{self.CPE_PATTERN.split(ecosystem, maxsplit=1)[-1]}"
        self.purl = purl


class Affected:
    """
    Class to hold affected data for a Vulnerability
    """

    # pylint: disable=too-few-public-methods
    # This class encapsulates Red Hat Affects
    # Only initialization is required because data retrieval is via JSON encoding

    def __init__(self, remediation: Remediation):
        self.package = Package(remediation.component, remediation.cpe,
                               remediation.purl)
        self.ranges = [Range(remediation.fixed_version)]


class OSV:
    """
    Class to convert CSAF data to OSV
    """
    SCHEMA_VERSION = "1.6.3"
    # Go package advisory reference prefix
    PKG_GO_DEV_VULN = "https://pkg.go.dev/vuln/"
    # Other common advisory prefixes in Red Hat Advisories
    ADVISORY_URL_PREFIXES = (
        PKG_GO_DEV_VULN,
        "https://www.cve.org/CVERecord",
        "https://nvd.nist.gov/vuln/detail/",
        "https://www.kb.cert.org/vuls/id/",
        "https://github.com/advisories/",
    )

    def __init__(self, csaf_data: CSAF):
        # Update this if verified against a later version
        self.schema_version = self.SCHEMA_VERSION

        self.id = csaf_data.id.upper()

        # This attribute is declared after id to make the resulting JSON human-readable. It can only
        # be populated after reading the csaf vulnerabilities and references sections.
        self.related: list[str] = []

        current_time = datetime.datetime.now(datetime.timezone.utc)
        self.published = current_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        self.modified = self.published

        self.summary = csaf_data.title

        # Set severity to the CVSS of the highest CVSSv3 base score
        highest_scoring_vuln = sorted(csaf_data.vulnerabilities,
                                      key=lambda x: x.cvss_v3_base_score)[-1]
        self.severity = [{
            "type": "CVSS_V3",
            "score": highest_scoring_vuln.cvss_v3_vector
        }]

        self.affected: list[Affected] = []
        for vulnerability in csaf_data.vulnerabilities:
            self.related.append(vulnerability.cve_id)
            for remediation in vulnerability.remediations:
                self.affected.append(Affected(remediation))

        self.references = self._convert_references(csaf_data)

    def _convert_references(self, csaf) -> list[dict[str, str]]:
        """
        CSAF has references for an advisory and each vulnerability has references as well.
        Collect this into a single references list for OSV and deduplicate them.
        """
        references: dict[str, str] = {}
        for reference in csaf.references:
            # This will capture both the Advisory URL and the CSAF document for the advisory
            if reference["category"] == "self":
                references[reference["url"]] = "ADVISORY"
            else:
                references[reference["url"]] = self._get_reference_type(
                    reference)
        for vulnerability in csaf.vulnerabilities:
            for reference in vulnerability.references:
                # This captures the CVE specific information
                if reference["category"] == "self":
                    references[reference["url"]] = "REPORT"
                else:
                    references[reference["url"]] = self._get_reference_type(
                        reference)
        return [{"type": t, "url": u} for u, t in references.items()]

    def _get_reference_type(self, reference: dict[str, str]) -> str:
        """
        Convert references from CSAF into typed referenced in OSV
        Also make sure to add a related entry for any GO advisory references found
        """
        if reference["url"].startswith(self.ADVISORY_URL_PREFIXES):
            self._add_go_related(reference["url"])
            return "ADVISORY"
        if reference["url"].startswith(
                "https://bugzilla.redhat.com/show_bug.cgi"):
            return "REPORT"
        return "ARTICLE"

    def _add_go_related(self, reference_url: str):
        """
        Check for GO Vulnerability Advisory references and add them to the OSV 'related' field
        """
        if reference_url.startswith(self.PKG_GO_DEV_VULN):
            self.related.append(
                reference_url.removeprefix(self.PKG_GO_DEV_VULN))
