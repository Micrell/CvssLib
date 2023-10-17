from models.cvss.abs.abc_cvss import CvssVersion, CvssSeverity
from models.cvss.cvss_v3 import *
from models.cvss.cvss_v31 import *

prim_dict_cvss_v31 = [{
    "source": "nvd@nist.gov",
    "type": "Primary",
    "cvssData": {
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "confidentialityImpact": "NONE",
        "integrityImpact": "NONE",
        "availabilityImpact": "HIGH",
        "baseScore": 7.5,
        "baseSeverity": "HIGH"
    },
    "exploitabilityScore": 3.9,
    "impactScore": 3.6
}]


def run():
    # test_cvss_v31_object_init_from_dict()
    # test_cvss_v31_object_init_from_vector_string()
    test_cvss_v31_env_score_computation()


def test_cvss_v31_object_init_from_vector_string() -> None:
    cvss_v31 = CvssV31.from_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
    assert cvss_v31.version == CvssVersion.CVSS_V31
    assert cvss_v31.attack_vector == AttackVector.NETWORK
    assert cvss_v31.attack_complexity == AttackComplexity.LOW
    assert cvss_v31.privileges_required == PrivilegesRequired.NONE
    assert cvss_v31.user_interaction == UserInteraction.NONE
    assert cvss_v31.confidentiality_impact == ConfidentialityImpact.NONE
    assert cvss_v31.integrity_impact == IntegrityImpact.NONE
    assert cvss_v31.availability_impact == AvailabilityImpact.HIGH
    assert cvss_v31.get_base_score() == 7.5
    assert cvss_v31.get_base_severity() == CvssSeverity.HIGH
    assert cvss_v31.get_vector_string() == "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:X/RL:X/RC:X/MAV:X/MAC:X/PR:X/MUI:X/MS:X/MC:X/MI:X/MA:X/CR:X/IR:X/AR:X/"


def test_cvss_v31_object_init_from_dict() -> None:
    cvss_v31 = CvssV31.from_primitive_dict(prim_dict_cvss_v31)
    assert cvss_v31.version == CvssVersion.CVSS_V31
    assert cvss_v31.attack_vector == AttackVector.NETWORK
    assert cvss_v31.attack_complexity == AttackComplexity.LOW
    assert cvss_v31.privileges_required == PrivilegesRequired.NONE
    assert cvss_v31.user_interaction == UserInteraction.NONE
    assert cvss_v31.confidentiality_impact == ConfidentialityImpact.NONE
    assert cvss_v31.integrity_impact == IntegrityImpact.NONE
    assert cvss_v31.availability_impact == AvailabilityImpact.HIGH
    assert cvss_v31.get_base_score() == 7.5
    assert cvss_v31.get_base_severity() == CvssSeverity.HIGH
    assert cvss_v31.get_vector_string() == "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:X/RL:X/RC:X/MAV:X/MAC:X/PR:X/MUI:X/MS:X/MC:X/MI:X/MA:X/CR:X/IR:X/AR:X/"


def test_cvss_v31_env_score_computation() -> None:
    cvss: CvssV31 = CvssV31.from_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/CR:X/IR:X/AR:X/MAV:P/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X")
    assert cvss.get_env_score() == 7.7