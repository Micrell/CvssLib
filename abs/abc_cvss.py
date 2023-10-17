from enum import Enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Self


class AbcVector(Enum):

    @classmethod
    def from_str(cls, value: str) -> Self:
        """
        Constructor with string as full word. Exemple: "HIGH"
        :param value:
        :return:
        """
        for elem in cls:
            if elem.value[0] == value:
                return cls(elem)
        raise  # todo create exception

    @classmethod
    def from_char(cls, value: str) -> Self:
        """
        Constructor with string as char. Exemple: "H" for "HIGH"
        :param value:
        :return:
        """
        for elem in cls:
            if elem.value[1] == value:
                return cls(elem)
        raise  # todo create exception

    def to_str(self, vector_initial: str) -> str:
        return f'{vector_initial}:{self.value[1]}/'

    def to_float(self, *args, **kwargs) -> float:
        return self.value[2]

    def __bool__(self) -> bool:
        if self.value[1] == "X":
            return False
        return True


class CvssSeverity(Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_float(cls, value: float) -> Self:
        if value == 0.0:
            return cls('None')
        elif 0.1 <= value <= 3.9:
            return cls('LOW')
        elif 4.0 <= value <= 6.9:
            return cls('MEDIUM')
        elif 7.0 <= value <= 8.9:
            return cls('HIGH')
        elif 9.0 <= value <= 10.0:
            return cls('CRITICAL')
        else:
            raise  # todo create exception

    def __str__(self) -> str:
        return self.value


class CvssVersion(Enum):
    CVSS_V2 = '2.0'
    CVSS_V30 = '3.0'
    CVSS_V31 = '3.1'

    @classmethod
    def from_str(cls, version: str) -> Self:
        """
        :param version: Should be '2.0', '3.0', '3.1'
        :return:
        """
        for elem in cls:
            if elem.value == version:
                return cls(elem)
        raise  # todo create exception

    def __str__(self) -> str:
        return self.value


@dataclass
class AbcCvss(ABC):

    version: CvssVersion
    _vector_string: str | None = field(init=False, default=None)
    _base_severity: CvssSeverity = field(init=False, default=None)
    _base_score: float = field(init=False, default=None)
    _env_score: float = field(init=False, default=None)

    @classmethod
    @abstractmethod
    def from_primitive_dict(cls, value: dict):
        pass

    @classmethod
    @abstractmethod
    def from_vector_string(cls, value: str):
        pass

    def set_base_score(self, value: float) -> None:
        """
        Set the attribute base_score safely.
        :param value: The value of the base score, if not between 0 and 10, it will try to compute the score.
        :return: None
        """
        if not 0 <= value <= 10:
            try:
                self._compute_base_score()
            except Exception as e:
                raise Exception
            finally:
                return None
        self._base_score = value
        return None

    def set_base_severity(self, value: float) -> None:
        try:
            self._base_severity = CvssSeverity.from_float(value)
        except Exception as e:
            raise Exception

    def set_env_score(self, value: float) -> None:
        self._env_score = value

    @abstractmethod
    def _compute_vector_string(self) -> str:
        pass

    def get_vector_string(self) -> str:
        return self._vector_string

    def get_base_score(self) -> float:
        return self._base_score

    def get_base_severity(self) -> CvssSeverity:
        return self._base_severity

    def get_env_score(self) -> float:
        return self._env_score

    @abstractmethod
    def _compute_base_score(self) -> float:
        """
        Should raise an error occurs
        :return:
        """
        pass

    @abstractmethod
    def _compute_env_score(self) -> float:
        pass

    @abstractmethod
    def _compute_exploitability_score(self) -> float:
        pass

    @abstractmethod
    def _compute_impact_score(self) -> float:
        pass

    @staticmethod
    def parse_vector_string(vector_string: str) -> dict[str, str]:
        """
        Parse a vector string and return a dictionnaire of metrics.
        Example: this method transform
        this str "AV:N/AC:L/Au:N/C:N/I:N/A:P"
        to this dict {'AV': 'N', 'AC': 'L', 'Au': 'N', 'C': 'N', 'I': 'N', 'A': 'P'}

        :param vector_string:
        :return: dict
        """
        result = {}
        pairs = vector_string.split("/")
        for pair in pairs:
            key, value = pair.split(":")
            result[key] = value
        return result
