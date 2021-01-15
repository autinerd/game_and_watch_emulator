from .periph import Periph
from .. import consts
from queue import Queue
class LTDC(Periph):
    BASE_ADDR = 0x5000_1000

    def __init__(self):
        self._SSCR = 0
        self._BPCR = 0
        self._AWCR = 0
        self._TWCR = 0
        self._GCR = 0x2220
        self._SRCR = 0
        self._BCCR = 0
        self._IER = 0
        self._ISR = 0
        self._ICR = 0
        self._LIPCR = 0
        self._CPSR = 0
        self._CDSR = 0
        self._L1CR = 0
        self._L2CR = 0
        self._L1WHPCR = 0
        self._L2WHPCR = 0
        self._L1WVPCR = 0
        self._L2WVPCR = 0
        self._L1WCKCR = 0
        self._L2WCKCR = 0
        self._L1PFCR = 0
        self._L2PFCR = 0
        self._L1CACR = 0xFF
        self._L2CACR = 0xFF
        self._L1DCCR = 0
        self._L2DCCR = 0
        self._L1BFCR = 0
        self._L2BFCR = 0
        self._L1CFBAR = 0
        self._L2CFBAR = 0
        self._L1CFBLR = 0
        self._L2CFBLR = 0
        self._L1CFBLNR = 0
        self._L2CFBLNR = 0
        self._L1CLUTWR = 0
        self._L2CLUTWR = 0

    def read_mem(self, address: int, size: int) -> int:
        if address == self.BASE_ADDR + 0x8:
            return self._SSCR
        elif address == self.BASE_ADDR + 0xC:
            return self._BPCR
        elif address == self.BASE_ADDR + 0x10:
            return self._AWCR
        elif address == self.BASE_ADDR + 0x14:
            return self._TWCR
        elif address == self.BASE_ADDR + 0x18:
            return self._GCR
        elif address == self.BASE_ADDR + 0x24:
            return self._SRCR
        elif address == self.BASE_ADDR + 0x2C:
            return self._BCCR
        elif address == self.BASE_ADDR + 0x34:
            return self._IER
        elif address == self.BASE_ADDR + 0x38:
            return self._ISR
        elif address == self.BASE_ADDR + 0x3C:
            return self._ICR
        elif address == self.BASE_ADDR + 0x40:
            return self._LIPCR
        elif address == self.BASE_ADDR + 0x44:
            return self._CPSR
        elif address == self.BASE_ADDR + 0x48:
            return self._CDSR
        elif address == self.BASE_ADDR + 0x84:
            return self._L1CR
        elif address == self.BASE_ADDR + 0x104:
            return self._L2CR
        elif address == self.BASE_ADDR + 0x88:
            return self._L1WHPCR
        elif address == self.BASE_ADDR + 0x108:
            return self._L2WHPCR
        elif address == self.BASE_ADDR + 0x8C:
            return self._L1WVPCR
        elif address == self.BASE_ADDR + 0x10C:
            return self._L2WVPCR
        elif address == self.BASE_ADDR + 0x90:
            return self._L1WCKCR
        elif address == self.BASE_ADDR + 0x110:
            return self._L2WCKCR
        elif address == self.BASE_ADDR + 0x94:
            return self._L1PFCR
        elif address == self.BASE_ADDR + 0x114:
            return self._L2PFCR
        elif address == self.BASE_ADDR + 0x98:
            return self._L1CACR
        elif address == self.BASE_ADDR + 0x118:
            return self._L2CACR
        elif address == self.BASE_ADDR + 0x9C:
            return self._L1DCCR
        elif address == self.BASE_ADDR + 0x11C:
            return self._L2DCCR
        elif address == self.BASE_ADDR + 0xA0:
            return self._L1BFCR
        elif address == self.BASE_ADDR + 0x120:
            return self._L2BFCR
        elif address == self.BASE_ADDR + 0xAC:
            return self._L1CFBAR
        elif address == self.BASE_ADDR + 0x12C:
            return self._L2CFBAR
        elif address == self.BASE_ADDR + 0xB0:
            return self._L1CFBLR
        elif address == self.BASE_ADDR + 0x130:
            return self._L2CFBLR
        elif address == self.BASE_ADDR + 0xB4:
            return self._L1CFBLNR
        elif address == self.BASE_ADDR + 0x134:
            return self._L2CFBLNR
        elif address == self.BASE_ADDR + 0xC4:
            return self._L1CLUTWR
        elif address == self.BASE_ADDR + 0x144:
            return self._L2CLUTWR

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR + 0x8:
            self.set_reg('_SSCR', 0x0FFF_07FF, data)
        elif address == self.BASE_ADDR + 0xC:
            self.set_reg('_BPCR', 0x0FFF_07FF, data)
        elif address == self.BASE_ADDR + 0x10:
            self.set_reg('_AWCR', 0x0FFF_07FF, data)
        elif address == self.BASE_ADDR + 0x14:
            self.set_reg('_TWCR', 0x0FFF_07FF, data)
        elif address == self.BASE_ADDR + 0x18:
            self.set_reg('_GCR', 0xF001_0001, data)
        elif address == self.BASE_ADDR + 0x24:
            self.set_reg('_SRCR', 0x0000_0003, data)
        elif address == self.BASE_ADDR + 0x2C:
            self.set_reg('_BCCR', 0x00FF_FFFF, data)
        elif address == self.BASE_ADDR + 0x34:
            self.set_reg('_IER', 0x0000_000F, data)
        elif address == self.BASE_ADDR + 0x3C:
            self._ISR &= ~data & 0xF
        elif address == self.BASE_ADDR + 0x40:
            self.set_reg('_LIPCR', 0x0000_0FFF, data)
        elif address == self.BASE_ADDR + 0x84:
            self.set_reg('_L1CR', 0x0000_0013, data)
        elif address == self.BASE_ADDR + 0x104:
            self.set_reg('_L2CR', 0x0000_0013, data)
        elif address == self.BASE_ADDR + 0x88:
            self.set_reg('_L1WHPCR', 0x0FFF_0FFF, data)
        elif address == self.BASE_ADDR + 0x108:
            self.set_reg('_L2WHPCR', 0x0FFF_0FFF, data)
        elif address == self.BASE_ADDR + 0x8C:
            self.set_reg('_L1WVPCR', 0x07FF_07FF, data)
        elif address == self.BASE_ADDR + 0x10C:
            self.set_reg('_L2WVPCR', 0x07FF_07FF, data)
        elif address == self.BASE_ADDR + 0x90:
            self.set_reg('_L1WCKCR', 0x00FF_FFFF, data)
        elif address == self.BASE_ADDR + 0x110:
            self.set_reg('_L2WCKCR', 0x00FF_FFFF, data)
        elif address == self.BASE_ADDR + 0x94:
            self.set_reg('_L1PFCR', 0x0000_0007, data)
        elif address == self.BASE_ADDR + 0x114:
            self.set_reg('_L2PFCR', 0x0000_0007, data)
        elif address == self.BASE_ADDR + 0x98:
            self.set_reg('_L1CACR', 0x0000_00FF, data)
        elif address == self.BASE_ADDR + 0x118:
            self.set_reg('_L2CACR', 0x0000_00FF, data)
        elif address == self.BASE_ADDR + 0x9C:
            self.set_reg('_L1DCCR', 0xFFFF_FFFF, data)
        elif address == self.BASE_ADDR + 0x11C:
            self.set_reg('_L2DCCR', 0xFFFF_FFFF, data)
        elif address == self.BASE_ADDR + 0xA0:
            self.set_reg('_L1BFCR', 0x0000_0707, data)
        elif address == self.BASE_ADDR + 0x120:
            self.set_reg('_L2BFCR', 0x0000_0707, data)
        elif address == self.BASE_ADDR + 0xAC:
            self.set_reg('_L1CFBAR', 0xFFFF_FFFF, data)
        elif address == self.BASE_ADDR + 0x12C:
            self.set_reg('_L2CFBAR', 0xFFFF_FFFF, data)
        elif address == self.BASE_ADDR + 0xB0:
            self.set_reg('_L1CFBLR', 0x1FFF_1FFF, data)
        elif address == self.BASE_ADDR + 0x130:
            self.set_reg('_L2CFBLR', 0x1FFF_1FFF, data)
        elif address == self.BASE_ADDR + 0xB4:
            self.set_reg('_L1CFBLNR', 0x0000_07FF, data)
        elif address == self.BASE_ADDR + 0x134:
            self.set_reg('_L2CFBLNR', 0x0000_07FF, data)
        elif address == self.BASE_ADDR + 0xC4:
            self.set_reg('_L1CLUTWR', 0xFFFF_FFFF, data)
        elif address == self.BASE_ADDR + 0x144:
            self.set_reg('_L2CLUTWR', 0xFFFF_FFFF, data)
