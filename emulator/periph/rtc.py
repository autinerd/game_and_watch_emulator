from .periph import Periph
import time

class RTC(Periph):
    BASE_ADDR = 0x5800_4000

    def __init__(self):
        self._TR = 0
        self._DR = 0x0000_2101
        self._SSR = 0
        self._ICSR = 0x7
        self._PRER = 0x007F_00FF
        self._WUTR = 0x0000_FFFF
        self._CR = 0
        self._WPR = 0
        self._CALR = 0
        self._SHIFTR = 0
        self._TSTR = 0
        self._TSDR = 0
        self._TSSSR = 0
        self._ALARMAR = 0
        self._ALRMASSR = 0
        self._ALRMBR = 0
        self._ALRMBSSR = 0
        self._SR = 0
        self._MISR = 0
        self._SCR = 0
        self._CFGR = 0

    def read_mem(self, address: int, size: int) -> int:
        t = time.localtime()
        if address == self.BASE_ADDR:
            return ((t.tm_hour // 10) << 20) + ((t.tm_hour % 10) << 16) + ((t.tm_min // 10) << 12) + ((t.tm_min % 10) << 8) + ((t.tm_sec // 10) << 4) + (t.tm_sec % 10)
        elif address == self.BASE_ADDR + 4:
            return ((t.tm_year % 100 // 10) << 20) + ((t.tm_year % 10) << 16) + ((t.tm_wday + 1) << 13) + ((t.tm_mon // 10) << 12) + ((t.tm_mon % 10) << 8) + ((t.tm_mday // 10) << 4) + (t.tm_mday % 10)
        elif address == self.BASE_ADDR + 0xC:
            return self._ICSR | (1 << 5) | (1 << 4)
        elif address == self.BASE_ADDR + 0x18:
            return self._CR
        return 0

    def write_mem(self, address: int, size: int, data: int):
        if address == self.BASE_ADDR + 0xC:
            self.set_reg('_ICSR', 0x0000_00A0, data)
            if self._ICSR & 0x80:
                self._ICSR |= 0x40
            else:
                self._ICSR &= (~0x40 & 0xFFFF_FFFF)
        elif address == self.BASE_ADDR + 0x18:
            self.set_reg('_CR', 0xE7FF_FF7F, data)
        pass
