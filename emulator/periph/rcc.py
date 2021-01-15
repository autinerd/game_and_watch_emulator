from .periph import Periph

class RCC(Periph):
    BASE_ADDR = 0x5802_4400

    def __init__(self):
        self._CR = 0x0000_0025
        self._HSICFGR = 0x4000_0000
        self._CSICFGR = 0x2000_0000
        self._CFGR = 0
        self._CDCFGR1 = 0
        self._CDCFGR2 = 0
        self._SRDCFGR = 0
        self._PLLCKSELR = 0x0202_0200
        self._PLLCFGR = 0x01FF_0000
        self._PLL1DIVR = 0x0101_0280
        self._PLL1FRACR = 0
        self._PLL2DIVR = 0x0101_0280
        self._PLL2FRACR = 0
        self._PLL3DIVR = 0x0101_0280
        self._PLL3FRACR = 0
        self._CDCCIPR = 0
        self._CDCCIP1R = 0
        self._CDCCIP2R = 0
        self._SRDCCIPR = 0
        self._CIER = 0
        self._BDCR = 0
        self._CSR = 2
        self._AHB1ENR = 0
        self._AHB3ENR = 0
        self._AHB4ENR = 0
        self._APB1LENR = 0
        self._APB2ENR = 0
        self._APB3ENR = 0
        self._APB4ENR = 0

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR + 0:
            return self._CR
        if address == self.BASE_ADDR + 4:
            return self._HSICFGR
        if address == self.BASE_ADDR + 0xC:
            return self._CSICFGR
        if address == self.BASE_ADDR + 0x10:
            return self._CFGR
        if address == self.BASE_ADDR + 0x18:
            return self._CDCFGR1
        if address == self.BASE_ADDR + 0x1C:
            return self._CDCFGR2
        if address == self.BASE_ADDR + 0x20:
            return self._SRDCFGR
        if address == self.BASE_ADDR + 0x28:
            return self._PLLCKSELR
        if address == self.BASE_ADDR + 0x2C:
            return self._PLLCFGR
        if address == self.BASE_ADDR + 0x30:
            return self._PLL1DIVR
        if address == self.BASE_ADDR + 0x34:
            return self._PLL1FRACR
        if address == self.BASE_ADDR + 0x38:
            return self._PLL2DIVR
        if address == self.BASE_ADDR + 0x3C:
            return self._PLL2FRACR
        if address == self.BASE_ADDR + 0x40:
            return self._PLL3DIVR
        if address == self.BASE_ADDR + 0x44:
            return self._PLL3FRACR
        if address == self.BASE_ADDR + 0x4C:
            return self._CDCCIPR
        if address == self.BASE_ADDR + 0x50:
            return self._CDCCIP1R
        if address == self.BASE_ADDR + 0x54:
            return self._CDCCIP2R
        if address == self.BASE_ADDR + 0x58:
            return self._SRDCCIPR
        if address == self.BASE_ADDR + 0x60:
            return self._CIER
        if address == self.BASE_ADDR + 0x70:
            return self._BDCR
        if address == self.BASE_ADDR + 0x74:
            return self._CSR
        if address == self.BASE_ADDR + 0x138:
            return self._AHB1ENR
        if address == self.BASE_ADDR + 0x134:
            return self._AHB3ENR
        if address == self.BASE_ADDR + 0x140:
            return self._AHB4ENR
        if address == self.BASE_ADDR + 0x148:
            return self._APB1LENR
        if address == self.BASE_ADDR + 0x150:
            return self._APB2ENR
        if address == self.BASE_ADDR + 0x144:
            return self._APB3ENR
        if address == self.BASE_ADDR + 0x154:
            return self._APB4ENR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR + 0:
            self.set_reg('_CR', 0x151D_129B, data)
            # Set PLL1RDY, PLL2RDY, PLL3RDY if the corresponding PLLxON is written
            if data & 0x0100_0000:
                self._CR |= 0x0200_0000
            else:
                self._CR &= 0xFDFF_FFFF
            if data & 0x0400_0000:
                self._CR |= 0x0800_0000
            else:
                self._CR &= 0xF7FF_FFFF
            if data & 0x1000_0000:
                self._CR |= 0x2000_0000
            else:
                self._CR &= 0xDFFF_FFFF
            if data & 0x80:
                self._CR |= 0x100
            else:
                self._CR &= 0xFFFF_FEFF
        if address == self.BASE_ADDR + 4:
            self.set_reg('_HSICFGR', 0x7F00_0000, data)
        if address == self.BASE_ADDR + 0xC:
            self.set_reg('_CSICFGR', 0x3F00_0000, data)
        if address == self.BASE_ADDR + 0x10:
            self.set_reg('_CFGR', 0xFFFC_BFC7, data)
            # Set SWS to the corresponding SW bits
            self._CFGR |= (data & 0x7) << 3
        if address == self.BASE_ADDR + 0x18:
            self.set_reg('_CDCFGR1', 0x0000_0F7F, data)
        if address == self.BASE_ADDR + 0x1C:
            self.set_reg('_CDCFGR2', 0x0000_0770, data)
        if address == self.BASE_ADDR + 0x20:
            self.set_reg('_SRDCFGR', 0x0000_0070, data)
        if address == self.BASE_ADDR + 0x28:
            self.set_reg('_PLLCKSELR', 0x03F3_F3F3, data)
        if address == self.BASE_ADDR + 0x2C:
            self.set_reg('_PLLCFGR', 0x01FF_0FFF, data)
        if address == self.BASE_ADDR + 0x30:
            self.set_reg('_PLL1DIVR', 0x7F7F_FFFF, data)
        if address == self.BASE_ADDR + 0x34:
            self.set_reg('_PLL1FRACR', 0x0000_FFF8, data)
        if address == self.BASE_ADDR + 0x38:
            self.set_reg('_PLL2DIVR', 0x7F7F_FFFF, data)
        if address == self.BASE_ADDR + 0x3C:
            self.set_reg('_PLL2FRACR', 0x0000_FFF8, data)
        if address == self.BASE_ADDR + 0x40:
            self.set_reg('_PLL3DIVR', 0x7F7F_FFFF, data)
        if address == self.BASE_ADDR + 0x44:
            self.set_reg('_PLL3FRACR', 0x0000_FFF8, data)
        if address == self.BASE_ADDR + 0x4C:
            self.set_reg('_CDCCIPR', 0x3001_0033, data)
        if address == self.BASE_ADDR + 0x50:
            self.set_reg('_CDCCIP1R', 0xB137_7FC7, data)
        if address == self.BASE_ADDR + 0x54:
            self.set_reg('_CDCCIP2R', 0x70F0_333F, data)
        if address == self.BASE_ADDR + 0x58:
            self.set_reg('_SRDCCIPR', 0x7803_FF07, data)
        if address == self.BASE_ADDR + 0x60:
            self.set_reg('_CIER', 0x0000_03FF, data)
        if address == self.BASE_ADDR + 0x70:
            if data & 1:
                self._BDCR |= 2
            else:
                self._BDCR &= 0xFFFF_FFFD
            self.set_reg('_BDCR', 0x0001_83BD, data)
        if address == self.BASE_ADDR + 0x74:
            self.set_reg('_CSR', 0x0000_0001, data)
        if address == self.BASE_ADDR + 0x138:
            self.set_reg('_AHB1ENR', 0x0600_0223, data)
        if address == self.BASE_ADDR + 0x134:
            self.set_reg('_AHB3ENR', 0x01E9_5031, data)
        if address == self.BASE_ADDR + 0x140:
            self.set_reg('_AHB4ENR', 0x3020_07FF, data)
        if address == self.BASE_ADDR + 0x148:
            self.set_reg('_APB1LENR', 0xE8FF_C3FF, data)
        if address == self.BASE_ADDR + 0x150:
            self.set_reg('_APB2ENR', 0x40D7_30F3, data)
        if address == self.BASE_ADDR + 0x144:
            self.set_reg('_APB3ENR', 0x0000_0048, data)
        if address == self.BASE_ADDR + 0x154:
            self.set_reg('_APB4ENR', 0x3020_07FF, data)
