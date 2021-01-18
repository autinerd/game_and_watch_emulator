from .unicorn import *
from .mmu import hook_mem_read, hook_mem_write, hook_mem_fetch, periphs, hook_code, message_input_queue, message_output_queue, lcd_interrupt_queue, _last_pc_values, hook_intr
from .hexfile_loader import read_hexfile
from sys import argv, stdout, stderr
import os
import struct
import threading
from .gui import GUIThread
import types

if len(argv) == 1:
    exit(1)

hexfile = None

for i in range(len(argv)):
    if argv[i] == '--hex' and len(argv) == i+2:
        hexfile = argv[i+1]
        break
    elif argv[i] == '--bin':
        if not os.path.exists('flash_backup.bin') or not os.path.exists('itcm_backup.bin') or not os.path.exists('internal_flash_backup.bin'):
            exit(2)
        break

mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

gui_thread = threading.Thread(target=GUIThread, args=(message_input_queue, message_output_queue, mu))
gui_thread.start()

# peripherals
mu.mem_map(0x4000_0000, 0xD400)
mu.mem_map(0x4001_0000, 0x8000)
mu.mem_map(0x4002_0000, 0x3400)
mu.mem_map(0x4004_0000, 0x4_0000)
mu.mem_map(0x4802_0000, 0x3000)
mu.mem_map(0x5000_1000, 0x3000)
mu.mem_map(0x5200_0000, 0xF000)
mu.mem_map(0x5800_0000, 0x7400)
mu.mem_map(0x5802_0000, 0x5C00)

# RAM
mu.mem_map(0x2400_0000, 0x10_0000)
mu.mem_map(0x3000_0000, 0x2_0000)
mu.mem_map(0x3800_0000, 0x1_0000)
mu.mem_map(0x0000_0000, 0x1_0000)
mu.mem_map(0x2000_0000, 0x2_0000)

# Flash
mu.mem_map(0x0800_0000, 0x2_0000)
mu.mem_map(0x1FF0_0000, 0x2_0000, perms=UC_PROT_READ)
mu.mem_map(0x9000_0000, 0x10_0000)

# Debug
mu.mem_map(0xE000_0000, 0x1_0000)

mu.mem_map(0xFFFF_F000, 0x1000)

mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_write)
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read)
mu.hook_add(UC_HOOK_MEM_FETCH, hook_mem_fetch)
mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_INTR, hook_intr)

if hexfile:
    data = read_hexfile(hexfile)

    for k, v in data.items():
        mu.mem_write(k, bytes(v))
else:
    with open('internal_flash_backup.bin', 'rb') as f:
        mu.mem_write(0x0800_0000, f.read())
    with open('flash_backup.bin', 'rb') as f:
        mu.mem_write(0x9000_0000, f.read())
    with open('itcm_backup.bin', 'rb') as f:
        mu.mem_write(0x0000_0000, f.read())

mu.reg_write(arm_const.UC_ARM_REG_SP, struct.unpack("<L", mu.mem_read(0x0800_0000, 4))[0])
try:
    mu.emu_start(struct.unpack("<L", mu.mem_read(0x0800_0004, 4))[0], 0xFFFF_FFFF)
except UcError as e:
    print(e)
    print(f'PC: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
    print(f'Content: {mu.mem_read(mu.reg_read(arm_const.UC_ARM_REG_PC), 4).hex()}')
    print([hex(i) for i in _last_pc_values])
    stdout.flush()
    stderr.flush()
    os._exit(0)
except KeyboardInterrupt:
    os._exit(0)
except Exception as ex:
    print(ex)
    print(ex.with_traceback())
    print(f'Content: {mu.mem_read(mu.reg_read(arm_const.UC_ARM_REG_PC), 4).hex()}')
    print(f'PC: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
    stdout.flush()
    stderr.flush()
    os._exit(0)
