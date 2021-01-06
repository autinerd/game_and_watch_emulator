from .periph import Periph

class PWR(Periph):
    BASE_ADDR = 0x5802_4800

    def __init__(self):
        self._CR1 = 0xF000_C000
        self._CSR1 = 0x6000
        self._CR3 = 6
        self._CPUCR = 0
        self._SRDCR = 0x6000
        self._WKUPEPR = 0

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR:
            return self._CR1
        elif address == self.BASE_ADDR + 4:
            return self._CSR1
        elif address == self.BASE_ADDR + 0xC:
            return self._CR3
        elif address == self.BASE_ADDR + 0x10:
            return self._CPUCR
        elif address == self.BASE_ADDR + 0x18:
            return self._SRDCR
        elif address == self.BASE_ADDR + 0x28:
            return self._WKUPEPR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR:
            self.set_reg('_CR1', 0x0FFF_F3F1, data)
        elif address == self.BASE_ADDR + 0xC:
            self.set_reg('_CR3', 0x0300_033F, data)
        elif address == self.BASE_ADDR + 0x10:
            self.set_reg('_CPUCR', 0x0000_0A05, data)
        elif address == self.BASE_ADDR + 0x18:
            self.set_reg('_SRDCR', 0x0000_C000, data)
        elif address == self.BASE_ADDR + 0x28:
            self.set_reg('_WKUPEPR', 0x0FFF_3F3F, data)
        
