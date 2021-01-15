from .periph import Periph

class SPI2(Periph):
    BASE_ADDR = 0x4000_3800

    def __init__(self):
        self._CR1 = 0
        self._CR2 = 0
        self._CFG1 = 0x7_0007
        self._CFG2 = 0
        self._IER = 0
        self._SR = 0x1002
        self._IFCR = 0
        self._TXDR = 0
        self._RXDR = 0
        self._CRCPOLY = 0x107
        self._TXCRC = 0
        self._RXCRC = 0
        self._UDRDR = 0
        self._I2SCFGR = 0

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR:
            return self._CR1
        elif address == self.BASE_ADDR + 4:
            return self._CR2
        elif address == self.BASE_ADDR + 8:
            return self._CFG1
        elif address == self.BASE_ADDR + 0xC:
            return self._CFG2
        elif address == self.BASE_ADDR + 0x10:
            return self._IER
        elif address == self.BASE_ADDR + 0x14:
            return self._SR
        elif address == self.BASE_ADDR + 0x18:
            return self._IFCR
        elif address == self.BASE_ADDR + 0x30:
            return self._RXDR
        elif address == self.BASE_ADDR + 0x40:
            return self._CRCPOLY
        elif address == self.BASE_ADDR + 0x44:
            return self._TXCRC
        elif address == self.BASE_ADDR + 0x48:
            return self._RXCRC
        elif address == self.BASE_ADDR + 0x4C:
            return self._UDRDR
        elif address == self.BASE_ADDR + 0x50:
            return self._I2SCFGR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR:
            self.set_reg('_CR1', 0x1_FF01, data)
        elif address == self.BASE_ADDR + 4:
            self.set_reg('_CR2', 0xFFFF_FFFF, data)
        elif address == self.BASE_ADDR + 8:
            self.set_reg('_CFG1', 0x705F_DFFF, data)
        elif address == self.BASE_ADDR + 0xC:
            self.set_reg('_CFG2', 0xF7FE_80FF, data)
        elif address == self.BASE_ADDR + 0x10:
            self.set_reg('_IER', 0x0000_0FFF, data)
        elif address == self.BASE_ADDR + 0x18:
            d = data & 0x0000_0FF8
            self._SR &= (~d & 0xFFFF_FFFF)
        elif address == self.BASE_ADDR + 0x20:
            self.set_reg('_TXDR', 0x0, data)
            if self._CR2 & 0xFFFF > 0:
                self._CR2 -= 1
                if self._CR2 & 0xFFFF == 0:
                    self._SR |= 0b1000
        elif address == self.BASE_ADDR + 0x30:
            self.set_reg('_RXDR', 0x0, data)
        elif address == self.BASE_ADDR + 0x40:
            self.set_reg('_CRCPOLY', 0x0, data)
        elif address == self.BASE_ADDR + 0x44:
            self.set_reg('_TXCRC', 0x0, data)
        elif address == self.BASE_ADDR + 0x48:
            self.set_reg('_RXCRC', 0x0, data)
        elif address == self.BASE_ADDR + 0x4C:
            self.set_reg('_UDRDR', 0x0, data)
        elif address == self.BASE_ADDR + 0x50:
            self.set_reg('_I2SCFGR', 0x0, data)
