from unicorn import unicorn_const, Uc, arm_const
from .periph import flash, rcc, pwr
import struct

FLASH = flash.FLASH()
PWR = pwr.PWR()
RCC = rcc.RCC()

def hook_mem_read(mu: Uc, access, address, size, value, user_data):
    try:
        if access == unicorn_const.UC_MEM_READ:
            data = 0
            if _between(address, 0x5200_2000, 0x5200_2FFF):
                data = FLASH.read_mem(address, size)
                mu.mem_write(address, struct.pack('<l', data))
                print("FLASH")
            elif _between(address, 0x5802_4400, 0x5802_47FF):
                data = RCC.read_mem(address, size)
                mu.mem_write(address, struct.pack('<l', data))
                print("RCC")
            elif _between(address, 0x5802_4800, 0x5802_4BFF):
                data = PWR.read_mem(address, size)
                mu.mem_write(address, struct.pack('<l', data))
                print("PWR")
            if address >= 0x4000_0000 and address <= 0x6000_0000:
                print(f'access: read,  address: 0x{address:08X}, data: 0x{data:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
    except KeyboardInterrupt:
        mu.emu_stop()
    
def hook_mem_write(mu, access, address, size, value, user_data):
    try:
        if access == unicorn_const.UC_MEM_WRITE:
            if _between(address, 0x5200_2000, 0x5200_2FFF):
                FLASH.write_mem(address, size, value)
                print("FLASH")
            elif _between(address, 0x5802_4400, 0x5802_47FF):
                RCC.write_mem(address, size, value)
                print("RCC")
            elif _between(address, 0x5802_4800, 0x5802_4BFF):
                PWR.write_mem(address, size, value)
                print("PWR")
            if address >= 0x4000_0000 and address <= 0x6000_0000:
                print(f'access: write, address: 0x{address:08X}, size: {size}, value: 0x{value:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
    except KeyboardInterrupt:
        mu.emu_stop()

def _between(val: int, min_val: int, max_val: int) -> bool:
    return val >= min_val and val <= max_val