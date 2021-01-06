#!/usr/bin/python3

def read_hexfile(filename: str) -> dict:
    f = open(filename, 'r')
    lines = f.readlines()
    f.close()
    current_addr = 0
    high_addr = 0
    start_addr = 0
    data = {}
    for line in lines:
        if line[0] != ':':
            return None
        size = int(line[1:3], base=16)
        low_addr = int(line[3:7], base=16)
        typ = int(line[7:9], base=16)
        if typ == 0:
            if (high_addr << 16) + low_addr > current_addr + 1:
                start_addr = (high_addr << 16) + low_addr
            if not start_addr in data:
                data[start_addr] = bytearray.fromhex(line[9:9+(size*2)])
            else:
                data[start_addr] += bytearray.fromhex(line[9:9+(size*2)])
            current_addr = (high_addr << 16) + low_addr + size
        elif typ == 4:
            high_addr = int(line[9:9+(size*2)], base=16)
    return data
