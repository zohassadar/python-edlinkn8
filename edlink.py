import os
import logging
import re
import zlib

from serial import Serial

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

STATE_LENGTH = 0x100

ADDR_SSR = 0x1802000
CMD_MEM_RD = 0x19

BAUD_RATE = 115200
IDENTIFIER = "EverDrive N8"


CMD_TEST = ord('t')
CMD_REBOOT = ord('r')
CMD_HALT = ord('h')
CMD_SEL_GAME = ord('n')
CMD_RUN_GAME = ord('s')



if os.name == "posix":
    from serial.tools.list_ports_posix import comports
elif os.name == "nt":
    from serial.tools.list_ports_windows import comports
else:
    raise ImportError("Unsupported os: {os.name}")

def to_string(data: bytearray):
    return '-'.join(f'{e:02x}'.upper() for e in data)

class Everdrive:
    def __init__(self):
        logger.debug(f"Initializing {type(self).__name__}()")
        self.set_serial_port()

    def set_serial_port(self):
        for port in comports():
            logger.debug(f"Found {port.device}: {port.description}")
            if port.description == IDENTIFIER:
                logger.info(f"Everdrive found on {port.device}")
                self.port = Serial(port=port.device, baudrate=BAUD_RATE)
                return
        raise RuntimeError(f"Unable to locate everdrive")

    def transmit_data(
        self,
        data: bytes,
        offset: int = 0,
        length: int = 0,
    ):
        if not length:
            length = len(data)
        BLOCK_SIZE = 8192
        logger.debug(f'Transmitting {length} of {len(data)} bytes starting at {offset}')
        while length > 0:
            block = BLOCK_SIZE
            if block > length:
                block = length
            chunk = data[offset:block]
            logger.debug(f"Attempting to write {len(chunk)} bytes")
            self.port.write(chunk)
            logger.debug(f"Wrote {len(chunk)} bytes")
            length -= block
            offset += block

    def receive_data(self, length: int) -> bytearray:
        logger.debug(f"Attempting to receive {length} bytes")
        data = self.port.read(length)
        logger.debug(f"Received {len(data)} bytes")
        return bytearray(data)
        
    def transmit_32(self, data: int):
        logger.debug(f"Sending 32 bits: 0x{data:08x}")
        self.transmit_data(bytearray(data.to_bytes(length=4, byteorder="little")))

    def transmit_8(self, data: int):
        logger.debug(f"Sending byte: 0x{data:02x}")
        self.transmit_data(bytearray([data & 0xff]))

    def transmit_command(self, command: int):
        logger.debug(f"Sending command: 0x{command:02x}")
        cmd = bytearray(4)
        cmd[0] = ord('+')
        cmd[1] = ord('+') ^ 0xFF
        cmd[2] = command
        cmd[3] = command ^ 0xFF
        self.transmit_data(cmd)

    def memory_read(
        self,
        address: int,
        length: int
    ):
        logger.debug(f"Attempting to read {length} bytes from 0x{address:08x}")
        self.transmit_command(CMD_MEM_RD)
        self.transmit_32(address)
        self.transmit_32(length)
        self.transmit_8(0)
        return self.receive_data(length)


    def print_state(self):
        state = self.memory_read(
            address=ADDR_SSR,
            length=STATE_LENGTH,
        )
        for i in range(0, STATE_LENGTH, 16):
            print(f"{to_string(state[i:i+8])}   {to_string(state[i+8:i+16])}")

class NesRom:
    ROM_TYPE_NES = 0
    MIR_HOR = 'H'
    MIR_VER = 'V'
    MIR_4SC = '4'
    MIR_1SC = '1'
    MAX_ID_CALC_LEN = 0x100000
    ADDR_PRG = 0x0000000
    ADDR_CHR = 0x0800000

    def __init__(self, path):
        self.rom_type = self.ROM_TYPE_NES
        if not (path):
            raise RuntimeError(f'No ROM specified')
        self.path = path
        self.rom = bytearray(bytes(open(path, 'rb').read()))
        self.size = len(self.rom)
        self.ines = self.rom[:32]
        self.nes = self.ines[0:3] == bytearray(b'NES')
        if not self.nes:
            raise RuntimeError(f"This script only supports nes")
        self.dat_base = 16
        self.prg_size = self.rom[4] * 1024 * 16
        self.chr_size = self.rom[5] * 1024 * 8
        self.srm_size = 8192
        if not self.prg_size:
            self.prg_size = 0x400000
        self.mapper = (self.rom[6] >> 4) | (self.rom[7] & 0xf0)
        self.mirroring = self.MIR_VER if self.rom[6] & 1 else self.MIR_HOR
        self.bat_ram = bool((self.rom[6] & 2))
        if self.rom[6] & 8:
            self.mirroring = self.MIR_4SC
        self.crc = zlib.crc32(self.rom[self.dat_base:])
        if self.mapper == 255:
            raise RuntimeError(f"OS mapper not yet supported")
        self.prg = self.rom[16:16+self.prg_size]
        self.chr = self.rom[16+self.prg_size:16+self.prg_size+self.chr_size]

        logger.info(f"{self.mapper=}")
        logger.info(f"{self.prg_size=}")
        logger.info(f"{self.chr_size=}")
        logger.info(f"{self.srm_size=}")
        logger.info(f"{self.mirroring=}")
        logger.info(f"{self.bat_ram=}")
        logger.info(f"{self.crc=:08x}")


    def get_rom_id(self):
        offset = len(self.ines)
        data = bytearray(offset + 12)
        data[:offset] = self.ines
        data[offset:offset+4] = bytearray(self.size.to_bytes(4, "little"))
        data[offset+4:offset+8] = bytearray(self.crc.to_bytes(4, "little"))
        data[offset+8:] = bytearray((16).to_bytes(4, "little"))
        return data
