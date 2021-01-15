from .periph import Periph

class OCTOSPIM(Periph):
    BASE_ADDR = 0x5200_B400

    def __init__(self):
        self._CR = 0
        self._P1CR = 0x0301_0111
        self._P2CR = 0x0705_0333

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR:
            return self._CR
        elif address == self.BASE_ADDR + 4:
            return self._P1CR
        elif address == self.BASE_ADDR + 8:
            return self._P2CR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR:
            self.set_reg('_CR', 0x00FF_0001, data)
        elif address == self.BASE_ADDR + 4:
            self.set_reg('_P1CR', 0x0707_0333, data)
        elif address == self.BASE_ADDR + 8:
            self.set_reg('_P2CR', 0x0707_0333, data)
