from .periph import Periph

class FLASH(Periph):
    BASE_ADDR = 0x5208_4400

    def __init__(self):
        self._CR = 0b0000_0000_0000_0000_0000_0000_0010_0101

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR + 0:
            return self._ACR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == 0x5200_2000 or address == 0x5200_2100:
            self._ACR = data & 0x151D_129B