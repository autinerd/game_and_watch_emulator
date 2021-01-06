from .periph import Periph

class FMC(Periph):
    BASE_ADDR = 0x5200_4000

    def __init__(self):
        self._BCR1 = 0x30DB
        self._BCR2 = 0x30D2
        self._BCR3 = 0x30D2
        self._BCR4 = 0x30D2
        self._PCR = 0x18
        self._SDCR1 = 0x2D0
        self._SDCR2 = 0x2D0

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR:
            return self._BCR1
        elif address == self.BASE_ADDR + 8:
            return self._BCR2
        elif address == self.BASE_ADDR + 16:
            return self._BCR3
        elif address == self.BASE_ADDR + 24:
            return self._BCR4
        elif address == self.BASE_ADDR + 0x80:
            return self._PCR
        elif address == self.BASE_ADDR + 0x140:
            return self._SDCR1
        elif address == self.BASE_ADDR + 0x144:
            return self._SDCR2
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR:
            self.set_reg('_BCR1', 0x833FFB7F, data)
        elif address == self.BASE_ADDR + 8:
            self.set_reg('_BCR2', 0x833FFB7F, data)
        elif address == self.BASE_ADDR + 16:
            self.set_reg('_BCR3', 0x833FFB7F, data)
        elif address == self.BASE_ADDR + 24:
            self.set_reg('_BCR4', 0x833FFB7F, data)
        elif address == self.BASE_ADDR + 0x80:
            return self._PCR
        elif address == self.BASE_ADDR + 0x140:
            return self._SDCR1
        elif address == self.BASE_ADDR + 0x144:
            return self._SDCR2