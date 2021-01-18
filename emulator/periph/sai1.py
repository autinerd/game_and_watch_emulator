from .periph import Periph

class SAI1(Periph):
    BASE_ADDR = 0x4001_5800

    def __init__(self):
        self._ACR1 = 0x40
        self._AIM = 0
        self._ASR = 0x1_0008

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR + 4:
            return self._ACR1
        elif address == self.BASE_ADDR + 0x14:
            return self._AIM
        elif address == self.BASE_ADDR + 0x18:
            return self._ASR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR + 4:
            self.set_reg('_ACR1', 0x0FFB_3FEF, data)
        elif address == self.BASE_ADDR + 0x14:
            self.set_reg('_AIM', 0x7F, data)
