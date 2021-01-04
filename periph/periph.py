from abc import ABC, abstractmethod

class Periph(ABC):
    @abstractmethod
    def read_mem(self, address: int, size: int) -> int:
        """
        Returns data to be read by the firmware.
        """
        pass

    @abstractmethod
    def write_mem(self, address: int, size: int, data: int):
        """
        Returns data to be read by the firmware.
        """
        pass