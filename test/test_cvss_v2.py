from abs.abc_cvss import CvssVersion, CvssSeverity
from cvss.cvss_v2 import CvssV2, AccessVector, AccessComplexity, Authentication, \
    ConfidentialityImpact, IntegrityImpact, AvailabilityImpact

prim_dict_cvss_v2 = [{
    "source": "nvd@nist.gov",
    "type": "Primary",
    "cvssData": {
        "version": "2.0",
        "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
        "accessVector": "NETWORK",
        "accessComplexity": "LOW",
        "authentication": "NONE",
        "confidentialityImpact": "NONE",
        "integrityImpact": "NONE",
        "availabilityImpact": "PARTIAL",
        "baseScore": 5
        },
    "baseSeverity": "MEDIUM",
    "exploitabilityScore": 10,
    "impactScore": 2.9,
    "acInsufInfo": False,
    "obtainAllPrivilege": False,
    "obtainUserPrivilege": False,
    "obtainOtherPrivilege": False,
    "userInteractionRequired": False
}]


def run():
    test_cvss_v2_object_init_from_dict()
    test_cvss_v2_object_init_from_vector_string()
    test_cvss_v2_base_score_computation()


def test_cvss_v2_object_init_from_vector_string() -> None:
    cvss_v2 = CvssV2.from_vector_string("AV:N/AC:L/Au:N/C:N/I:N/A:P")
    assert cvss_v2.version == CvssVersion.CVSS_V2
    assert cvss_v2.access_vector == AccessVector.NETWORK
    assert cvss_v2.access_complexity == AccessComplexity.LOW
    assert cvss_v2.authentication == Authentication.NONE
    assert cvss_v2.confidentiality_impact == ConfidentialityImpact.NONE
    assert cvss_v2.integrity_impact == IntegrityImpact.NONE
    assert cvss_v2.availability_impact == AvailabilityImpact.PARTIAL
    assert cvss_v2.get_base_score() == 5
    assert cvss_v2.get_base_severity() == CvssSeverity.MEDIUM
    assert cvss_v2.get_vector_string() == "AV:N/AC:L/Au:N/C:N/I:N/A:P/E:ND/RL:ND/RC:ND/"


def test_cvss_v2_object_init_from_dict() -> None:
    cvss_v2 = CvssV2.from_primitive_dict(prim_dict_cvss_v2)
    assert cvss_v2.version == CvssVersion.CVSS_V2
    assert cvss_v2.access_vector == AccessVector.NETWORK
    assert cvss_v2.access_complexity == AccessComplexity.LOW
    assert cvss_v2.authentication == Authentication.NONE
    assert cvss_v2.confidentiality_impact == ConfidentialityImpact.NONE
    assert cvss_v2.integrity_impact == IntegrityImpact.NONE
    assert cvss_v2.availability_impact == AvailabilityImpact.PARTIAL
    assert cvss_v2.get_base_score() == 5
    assert cvss_v2.get_base_severity() == CvssSeverity.MEDIUM
    assert cvss_v2.get_vector_string() == "AV:N/AC:L/Au:N/C:N/I:N/A:P/E:ND/RL:ND/RC:ND/"


def test_cvss_v2_base_score_computation() -> None:
    assert CvssV2.from_vector_string("AV:L/AC:H/Au:M/C:N/I:N/A:N").get_base_score() == 0
    assert CvssV2.from_vector_string("AV:A/AC:L/Au:N/C:N/I:N/A:N").get_base_score() == 0
    assert CvssV2.from_vector_string("AV:N/AC:L/Au:N/C:N/I:N/A:N").get_base_score() == 0
    assert CvssV2.from_vector_string("AV:L/AC:M/Au:M/C:N/I:N/A:N").get_base_score() == 0
    assert CvssV2.from_vector_string("AV:L/AC:L/Au:M/C:N/I:N/A:N").get_base_score() == 0
    assert CvssV2.from_vector_string("AV:L/AC:H/Au:S/C:N/I:N/A:N").get_base_score() == 0
    assert CvssV2.from_vector_string("AV:L/AC:H/Au:N/C:N/I:N/A:N").get_base_score() == 0

    assert CvssV2.from_vector_string("AV:L/AC:H/Au:M/C:P/I:N/A:N").get_base_score() == 0.8
    assert CvssV2.from_vector_string("AV:L/AC:H/Au:M/C:C/I:N/A:N").get_base_score() == 3.7

    assert CvssV2.from_vector_string("AV:L/AC:H/Au:M/C:N/I:P/A:N").get_base_score() == 0.8
    assert CvssV2.from_vector_string("AV:L/AC:H/Au:M/C:N/I:C/A:N").get_base_score() == 3.7

    assert CvssV2.from_vector_string("AV:L/AC:H/Au:M/C:N/I:N/A:P").get_base_score() == 0.8
    assert CvssV2.from_vector_string("AV:L/AC:H/Au:M/C:N/I:N/A:C").get_base_score() == 3.7

    assert CvssV2.from_vector_string("AV:L/AC:H/Au:M/C:P/I:P/A:P").get_base_score() == 3.4
    assert CvssV2.from_vector_string("AV:L/AC:H/Au:M/C:C/I:C/A:C").get_base_score() == 5.9

    assert CvssV2.from_vector_string("AV:A/AC:M/Au:S/C:C/I:C/A:C").get_base_score() == 7.4
    assert CvssV2.from_vector_string("AV:N/AC:L/Au:N/C:C/I:C/A:C").get_base_score() == 10.0

    assert CvssV2.from_vector_string("AV:N/AC:M/Au:S/C:C/I:C/A:C").get_base_score() == 8.5
