from __future__ import annotations
import os
import logging
import pathlib
import re
import zlib

from serial import Serial

# logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

STATE_LENGTH = 0x100

ACK_BLOCK_SIZE = 1024
FAT_READ = 0x01

CMD_STATUS = 0x10
CMD_F_FOPN = 0xC9
CMD_F_FCLOSE = 0xCE
CMD_F_FINFO = 0xD0
CMD_F_FRD = 0xCA
CMD_FPG_SDC = 0x1F
ADDR_SSR = 0x1802000
ADDR_FIFO = 0x1810000
CMD_MEM_RD = 0x19
CMD_MEM_WR = 0x1A
CMD_FPG_USB = 0x1E

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



class FileInfo:
    name: str
    size: int
    date: int
    time: int
    attrib: int


class Everdrive:
    def __init__(self):
        logger.debug(f"Initializing {type(self).__name__}()")
        self.set_serial_port()

    def set_serial_port(self):
        for port in comports():
            logger.debug(f"Found {port.device}: {port.description}")
            if port.description == IDENTIFIER:
                logger.info(f"Everdrive found on {port.device}")
                self.port = Serial(port=port.device, baudrate=BAUD_RATE,timeout=2)
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
        BLOCK_SIZE = 1024
        logger.info(f"Transmitting {len(data)}: {data[:48].hex()}")
        while length > 0:
            block = BLOCK_SIZE
            if block > length:
                block = length
            chunk = data[offset:offset+block]
            self.port.write(chunk)
            length -= block
            offset += block

    def receive_data(self, length: int) -> bytearray:
        data = self.port.read(length)
        data = bytearray(data)
        logger.info(f"Received {len(data)}: {data[:48].hex()}")
        return data

    def transmit_command(self, command: int):
        cmd = bytearray(4)
        cmd[0] = ord('+')
        cmd[1] = ord('+') ^ 0xFF
        cmd[2] = command
        cmd[3] = command ^ 0xFF
        self.transmit_data(cmd)
        logger.info(f"Transmitting command: {cmd.hex()}")

    def memory_read(
        self,
        address: int,
        length: int
    ):
        logger.info(f"Reading: {length} from 0x{address:08x}")
        self.transmit_command(CMD_MEM_RD)
        self.transmit_32(address)
        self.transmit_32(length)
        self.transmit_8(0)
        return self.receive_data(length)

    def memory_write(self, address: int, data: bytearray):
        length = len(data)
        logger.info(f"Writing {length} to {address:08x}")
        self.transmit_command(CMD_MEM_WR)
        self.transmit_32(address)
        self.transmit_32(length)
        self.transmit_8(0)
        self.transmit_data(data)
    
    def receive_8(self):
        result = self.receive_data(1).pop()
        logger.info(f"receive_8: {result:02x}")
        return result
    
    def receive_16(self):
        result = self.receive_data(2)
        result = result[1] << 8 | result[0]
        logger.info(f"receive_16: {result:04x}")
        return result
    
    def receive_32(self):
        result = self.receive_data(4)
        result = result[0] | (result[1] << 8) | (result[2] << 16) | (result[3] << 24)
        logger.info(f"receive_16: {result:08x}")
        return result
    
    def transmit_32(self, data: int):
        logger.debug(f"Sending 32 bits: 0x{data:08x}")
        self.transmit_data(bytearray(data.to_bytes(length=4, byteorder="little")))
    
    def transmit_16(self, data: int):
        logger.debug(f"Sending 16 bits: 0x{data:04x}")
        self.transmit_data(bytearray(data.to_bytes(length=2, byteorder="little")))

    def transmit_8(self, data: int):
        logger.debug(f"Sending byte: 0x{data:02x}")
        self.transmit_data(bytearray([data & 0xff]))

    def print_state(self):
        state = self.memory_read(
            address=ADDR_SSR,
            length=STATE_LENGTH,
        )
        for i in range(0, STATE_LENGTH, 16):
            print(f"{to_string(state[i:i+8])}   {to_string(state[i+8:i+16])}")

    def write_fifo(self, data: bytearray):
        self.memory_write(ADDR_FIFO, data)

    def transmit_string_fifo(self, message: str):
        length = bytearray(len(message).to_bytes(2, "little"))
        data = bytearray(message.encode())
        logger.info(f"string fifo: {length.hex()} {data.hex()}")
        self.write_fifo(length)
        self.write_fifo(data)

    def transmit_string(self, message: str):
        length = bytearray(len(message).to_bytes(2, "little"))
        data = bytearray(message.encode())
        logger.info(f"string: {length.hex()} {data.hex()}")
        self.transmit_data(length)
        self.transmit_data(data)


    def command(self, command):
        data = bytearray(2)
        data[0] = ord("*")
        data[1] = command
        logger.info(f"command: {data.hex()}") 
        self.write_fifo(data)

    def load_game(self, rom: NesRom):
        logger.info(f"Sending command to select game")
        self.command(CMD_SEL_GAME)

        rom_name = f"USB:{rom.name}"
        self.transmit_string_fifo(rom_name)
        logger.info(f"Received: {self.receive_8()}")

        logger.info(f"writing rom id to fifo")
        rom_id = rom.get_rom_id()

        logger.info(f"rom id: {'-'.join(f'{b:02x}'.upper() for b in rom_id)}")
        self.write_fifo(rom_id)
        logger.info(f"Received: {self.receive_8()}")


        logger.info(f"getting 2 bytes for map_idx")
        map_idx = self.receive_16()


        logger.info(f"Running the game:  {map_idx}")
        self.command(CMD_RUN_GAME)
        logger.info(f"Received: {self.receive_8()}")
        self.memory_write(rom.ADDR_PRG, rom.prg)
        self.memory_write(rom.ADDR_CHR, rom.chr)
        self.map_load_sdc(map_idx)

    def fpg_init_direct(self):
        fpg = bytearray(open('004.RBF', 'rb').read())
        self.transmit_command(CMD_FPG_USB)
        self.transmit_32(len(fpg))
        self.transmit_data_ack(fpg)
        self.check_status()


    def file_info(self, path: str):
        logger.info(f"Requesting file info")
        self.transmit_command(CMD_F_FINFO)
        self.transmit_string(path)
        response = self.receive_8()
        if response:
            raise RuntimeError(f"File access error: {response:02x}")
        return self.receive_file_info()

    def receive_file_info(self) -> FileInfo:
        logger.info(f"Receiving file info")
        fileinfo = FileInfo()
        fileinfo.size = self.receive_32()
        fileinfo.date = self.receive_16()
        fileinfo.time = self.receive_16()
        fileinfo.attrib = self.receive_8()
        fileinfo.name = self.receive_string()
        return fileinfo

    def receive_string(self):
        length = self.receive_16()
        logger.info(f"Receiving String of {length} length")
        data = self.receive_data(length)
        return bytes(data).decode()

    def fpg_init(self, path: str):
        logger.info(f"Initializing FPG: {path}")
        # fileinfo = self.file_info(path)
        self.open_file(path, FAT_READ)
        self.transmit_command(CMD_FPG_SDC)
        self.transmit_32(129536)
        self.transmit_8(0)
        self.check_status()

    def check_status(self):
        logger.info(f"Checking Status")
        response = self.get_status()
        if response:
            raise RuntimeError(f"Operation error: {response:02x}")

    def get_status(self):
        self.transmit_command(CMD_STATUS)
        response = self.receive_16()
        if (response & 0xff00) != 0xA500:
            raise RuntimeError(f"Unexpected response: {response:04x}")
        return response & 0xff


    def transmit_data_ack(self, data):
        length = len(data)
        offset = 0
        while length > 0:
            response = self.receive_8()
            if response:
                raise RuntimeError(f"Tx ack: {response:02x}")
            block = ACK_BLOCK_SIZE
            if block > length:
                block = length
            self.transmit_data(data[offset:offset+block])
            length -= block
            offset += block


    def map_load_sdc(self, map_id: int):
        logger.debug('YO WE ARE TRYING TO MAP LOAD SDC')
        map_path = "EDN8/MAPS/"
        self.open_file("EDN8/MAPROUT.BIN", FAT_READ)
        logger.info(f"Opened file in map_load_sdc")
        map_data = self.read_file(4096)
        logger.info(f"read data in map_load_sdc")
        self.close_file()

        map_pkg = map_data[map_id]
        if map_pkg < 100:
            map_path += "0"
        if map_pkg < 10:
            map_path += "0"
        map_path = f'{map_path}{map_pkg}.RBF'
        logger.info(f"int mapper: {map_path}")
        self.fpg_init(map_path)
        
    def open_file(self, path: str, mode: int):
        logger.info(f"Opening: {path}")
        self.transmit_command(CMD_F_FOPN)
        logger.info(f"File open command: {CMD_F_FOPN}")
        self.transmit_8(mode)
        logger.info(f"File open mode: {mode}")
        self.transmit_string(path)
        logger.info(f"File open path: {path}")
        self.check_status()

    def close_file(self):
        logger.debug(f"CLOSING FILE")
        self.transmit_command(CMD_F_FCLOSE)
        self.check_status()

    def read_file(self, length: int) -> bytearray:
        logger.debug("Receiving data from file")
        self.transmit_command(CMD_F_FRD)
        self.transmit_32(length)
        data = bytearray(length)
        offset = 0
        while length > 0:
            block = 4096
            if block > length:
                block = length
            response = self.receive_8()
            if response:
                raise Exception(f"File read error: {response:02x}")
            data[offset:offset+block] = self.receive_data(block)
            offset += block
            length -= block
        return data


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

    @property
    def name(self):
        return pathlib.Path(self.path).name

    def get_rom_id(self):
        logger.debug('Getting rom ID')
        offset = len(self.ines)
        data = bytearray(offset + 12)
        data[:offset] = self.ines
        data[offset:offset+4] = bytearray(self.size.to_bytes(4, "little"))
        data[offset+4:offset+8] = bytearray(self.crc.to_bytes(4, "little"))
        data[offset+8:] = bytearray((16).to_bytes(4, "little"))
        return data

e = Everdrive()
r = NesRom('../TetrisGYM/clean.nes')
e.load_game(r)
