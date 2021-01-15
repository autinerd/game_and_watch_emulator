from .periph import Periph

class TIM5(Periph):
    BASE_ADDR = 0x4000_0C00

    def __init__(self):
        self._CR1 = 0
        self._DIER = 0
        self._SR = 0
        self._EGR = 0
        self._CNT = 0
        self._PSC = 0
        self._ARR = 0xFFFF_FFFF

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR:
            return self._CR1
        elif address == self.BASE_ADDR + 0xC:
            return self._DIER
        elif address == self.BASE_ADDR + 0x10:
            return self._SR
        elif address == self.BASE_ADDR + 0x14:
            return self._EGR
        elif address == self.BASE_ADDR + 0x24:
            return self._CNT
        elif address == self.BASE_ADDR + 0x28:
            return self._PSC
        elif address == self.BASE_ADDR + 0x2C:
            return self._ARR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR:
            self.set_reg('_CR1', 0x0BFF, data)
        elif address == self.BASE_ADDR + 0xC:
            self.set_reg('_DIER', 0x5F5F, data)
        elif address == self.BASE_ADDR + 0x10:
            self.set_reg('_SR', 0x1E5F, data)
        elif address == self.BASE_ADDR + 0x14:
            self.set_reg('_EGR', 0x005F, data)
            if self._EGR & 1:
                self._SR |= 1
                self._EGR &= ~1 & 0xFFFF_FFFF
        elif address == self.BASE_ADDR + 0x24:
            self.set_reg('_CNT', 0xFFFF_FFFF, data)
        elif address == self.BASE_ADDR + 0x28:
            self.set_reg('_PSC', 0xFFFF, data)
        elif address == self.BASE_ADDR + 0x2C:
            self.set_reg('_ARR', 0xFFFF_FFFF, data)
