from unicorn import unicorn_const, Uc, arm_const
from .periph import *
import struct

periphs = [
    ("FLASH", flash.FLASH(), 0x5200_2000, 0x5200_2FFF),
    ("RCC", rcc.RCC(), 0x5802_4400, 0x5802_47FF),
    ("PWR", pwr.PWR(), 0x5802_4800, 0x5802_4BFF),
    ("GPIOA", gpioa.GPIOA(), 0x5802_0000, 0x5802_03FF),
    ("GPIOB", gpiob.GPIOB(), 0x5802_0400, 0x5802_07FF),
    ("GPIOC", gpioc.GPIOC(), 0x5802_0800, 0x5802_0BFF),
    ("GPIOD", gpiod.GPIOD(), 0x5802_0C00, 0x5802_0FFF),
    ("GPIOE", gpioe.GPIOE(), 0x5802_1000, 0x5802_13FF),
    ("GPIOF", gpiof.GPIOF(), 0x5802_1400, 0x5802_17FF),
    ("GPIOG", gpiog.GPIOG(), 0x5802_1800, 0x5802_1BFF),
    ("GPIOH", gpioh.GPIOH(), 0x5802_1C00, 0x5802_1FFF),
    ("GPIOI", gpioi.GPIOI(), 0x5802_2000, 0x5802_23FF),
    ("GPIOJ", gpioj.GPIOJ(), 0x5802_2400, 0x5802_27FF),
    ("GPIOK", gpiok.GPIOK(), 0x5802_2800, 0x5802_2BFF),
    ("FMC", fmc.FMC(), 0x5200_4000, 0x5200_4FFF),
    ("LTDC", ltdc.LTDC(), 0x5000_1000, 0x5000_1FFF)
]

def hook_mem_read(mu: Uc, access, address, size, value, user_data):
    try:
        if access == unicorn_const.UC_MEM_READ:
            data = 0
            for periph in periphs:
                if _between(address, periph[2], periph[3]):
                    data = periph[1].read_mem(address, size)
                    mu.mem_write(address, struct.pack('<L', data))
                    print(periph[0])
                    break
            if address >= 0x4000_0000 and address <= 0x6000_0000:
                print(f'access: read,  address: 0x{address:08X}, data: 0x{data:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
        elif access == unicorn_const.UC_MEM_READ_UNMAPPED:
            print(f'access unmapped memory: read,  address: 0x{address:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
    except KeyboardInterrupt:
        mu.emu_stop()
    
def hook_mem_write(mu, access, address, size, value, user_data):
    try:
        if access == unicorn_const.UC_MEM_WRITE:
            for periph in periphs:
                if _between(address, periph[2], periph[3]):
                    periph[1].write_mem(address, size, value)
                    print(periph[0])
                    break
            if address >= 0x4000_0000 and address <= 0x6000_0000:
                print(f'access: write, address: 0x{address:08X}, value: 0x{value:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
        elif access == unicorn_const.UC_MEM_READ_UNMAPPED:
            print(f'access unmapped memory: write,  address: 0x{address:08X}, value: 0x{value:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
    except KeyboardInterrupt:
        mu.emu_stop()

def _between(val: int, min_val: int, max_val: int) -> bool:
    return val >= min_val and val <= max_val