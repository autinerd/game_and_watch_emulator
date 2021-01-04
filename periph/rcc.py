from .periph import Periph

class RCC(Periph):
    BASE_ADDR = 0x5208_4400

    def __init__(self):
        self._CR = 0x25
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
        self._CSR = 0
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
            self._CR = data & 0x151D_129B
        if address == self.BASE_ADDR + 4:
            self._HSICFGR = data & 0x7F00_0000
        if address == self.BASE_ADDR + 0xC:
            self._CSICFGR = data & 0x3F00_0000
        if address == self.BASE_ADDR + 0x10:
            self._CFGR = data & 0xFFFC_BFC7
        if address == self.BASE_ADDR + 0x18:
            self._CDCFGR1 = data & 0x0000_0F7F
        if address == self.BASE_ADDR + 0x1C:
            self._CDCFGR2 = data & 0x0000_0770
        if address == self.BASE_ADDR + 0x20:
            self._SRDCFGR = data & 0x0000_0070
        if address == self.BASE_ADDR + 0x28:
            self._PLLCKSELR = data & 0x03F3_F3F3
        if address == self.BASE_ADDR + 0x2C:
            self._PLLCFGR = data & 0x01FF_0FFF
        if address == self.BASE_ADDR + 0x30:
            self._PLL1DIVR = data & 0x7F7F_FFFF
        if address == self.BASE_ADDR + 0x34:
            self._PLL1FRACR = data & 0x0000_FFF8
        if address == self.BASE_ADDR + 0x38:
            self._PLL2DIVR = data & 0x7F7F_FFFF
        if address == self.BASE_ADDR + 0x3C:
            self._PLL2FRACR = data & 0x0000_FFF8
        if address == self.BASE_ADDR + 0x40:
            self._PLL3DIVR = data & 0x7F7F_FFFF
        if address == self.BASE_ADDR + 0x44:
            self._PLL3FRACR = data & 0x0000_FFF8
        if address == self.BASE_ADDR + 0x4C:
            self._CDCCIPR = data & 0x3001_0033
        if address == self.BASE_ADDR + 0x50:
            self._CDCCIP1R = data & 0xB137_7FC7
        if address == self.BASE_ADDR + 0x54:
            self._CDCCIP2R = data & 0x70F0_333F
        if address == self.BASE_ADDR + 0x58:
            self._SRDCCIPR = data & 0x7803_FF07
        if address == self.BASE_ADDR + 0x60:
            self._CIER = data & 0x0000_03FF
        if address == self.BASE_ADDR + 0x70:
            self._BDCR = data & 0x0001_83BD
        if address == self.BASE_ADDR + 0x74:
            self._CSR = data & 0x0000_0001
        if address == self.BASE_ADDR + 0x138:
            self._AHB1ENR = data & 0x0600_0223
        if address == self.BASE_ADDR + 0x134:
            self._AHB3ENR = data & 0x01E9_5031
        if address == self.BASE_ADDR + 0x140:
            self._AHB4ENR = data & 0x3020_07FF
        if address == self.BASE_ADDR + 0x148:
            self._APB1LENR = data & 0xE8FF_C3FF
        if address == self.BASE_ADDR + 0x150:
            self._APB2ENR = data & 0x40D7_30F3
        if address == self.BASE_ADDR + 0x144:
            self._APB3ENR = data & 0x0000_0048
        if address == self.BASE_ADDR + 0x154:
            self._APB4ENR = data & 0x3020_07FF