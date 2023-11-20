import os
import re
from serial import Serial
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

STATE_LENGTH = 0x100

ADDR_SSR = 0x1802000
CMD_MEM_RD = 0x19

BAUD_RATE = 115200
IDENTIFIER = "EverDrive N8"


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
