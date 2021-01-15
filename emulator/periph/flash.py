from .periph import Periph

class FLASH(Periph):
    BASE_ADDR = 0x5200_2000

    def __init__(self):
        self._ACR = 0x13

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR or address == self.BASE_ADDR + 0x100:
            return self._ACR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR or address == self.BASE_ADDR + 0x100:
            self.set_reg('_ACR', 0x0000_003F, data)
