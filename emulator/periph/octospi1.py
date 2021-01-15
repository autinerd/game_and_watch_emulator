from .periph import Periph

class OCTOSPI1(Periph):
    BASE_ADDR = 0x5200_5000

    def __init__(self):
        self._CR = 0
        self._SR = 0
        self._IR = 0

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR:
            return self._CR
        elif address == self.BASE_ADDR + 0x20:
            return self._SR
        elif address == self.BASE_ADDR + 0x110:
            return self._IR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR:
            self.set_reg('_CR', 0x30DF_1FCF, data)
        elif address == self.BASE_ADDR + 0x110:
            self.set_reg('_IR', 0xFFFF_FFFF, data)
            self._SR |= 0b10
        elif address == self.BASE_ADDR + 0x24: # _FCR
            d = data & 0x1B
            self._SR &= ~d & 0xFFFF_FFFF
