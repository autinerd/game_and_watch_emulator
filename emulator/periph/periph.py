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

    def set_reg(self, reg_name: str, mask: int, value: int):
        if reg_name in vars(self):
            vars(self)[reg_name] = (value & mask) | (vars(self)[reg_name] & (~mask & 0xFFFF_FFFF))