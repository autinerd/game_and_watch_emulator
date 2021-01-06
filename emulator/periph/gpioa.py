from .periph import Periph

class GPIOA(Periph):
    BASE_ADDR = 0x5802_0000

    def __init__(self):
        self._MODER = 0xABFF_FFFF
        self._OTYPER = 0
        self._OSPEEDR = 0x0C00_0000
        self._PUPDR = 0x6400_0000
        self._IDR = 0
        self._ODR = 0
        self._BSRR = 0
        self._LCKR = 0
        self._AFRL = 0
        self._AFRH = 0