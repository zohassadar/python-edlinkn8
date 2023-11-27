"""
Thanks to Krikzz
https://github.com/krikzz/EDN8-PRO
"""

from __future__ import annotations
import argparse
import base64
import hashlib
import logging
import os
import pathlib
import sys
import zlib

from serial import Serial

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TEST_ROM_LEN = 40976
TEST_ROM_SHA1SUM = "ea914304489deade0a3ef598b4a7e5dc0d558c59"

STATE_LENGTH = 0x100

BLOCK_SIZE = 8192
ACK_BLOCK_SIZE = 1024

FAT_READ = 0x01

CMD_STATUS = 0x10
CMD_MEM_RD = 0x19
CMD_MEM_WR = 0x1A
CMD_FPG_USB = 0x1E
CMD_FPG_SDC = 0x1F
CMD_F_FOPN = 0xC9
CMD_F_FRD = 0xCA
CMD_F_FCLOSE = 0xCE
CMD_F_FINFO = 0xD0

ADDR_SSR = 0x1802000
ADDR_FIFO = 0x1810000

BAUD_RATE = 115200
IDENTIFIER = "EverDrive N8"

CMD_TEST = ord("t")
CMD_REBOOT = ord("r")
CMD_HALT = ord("h")
CMD_SEL_GAME = ord("n")
CMD_RUN_GAME = ord("s")


if os.name == "posix":
    from serial.tools.list_ports_posix import comports
elif os.name == "nt":
    from serial.tools.list_ports_windows import comports
else:
    raise ImportError("Unsupported os: {os.name}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("rom", nargs="?", help="Load this rom")
    parser.add_argument("-p", "--patch", help="Apply .ips patch to rom first")
    parser.add_argument("-t", "--test", action="store_true", help="Launch test rom")
    parser.add_argument("-s", "--sha1sum", help="sha1sum to validate patch", default="")
    parser.add_argument("-S", "--print-state", action="store_true")
    args = parser.parse_args()
    everdrive = Everdrive()
    if args.patch:
        rom = open_rom_with_patch(args.rom, args.patch, args.sha1sum)
        rom = NesRom(rom=rom, name=args.patch.replace(".ips", ".nes"))
        everdrive.load_game(rom)
    elif args.rom:
        rom = NesRom.from_file(args.rom)
        everdrive.load_game(rom)
    elif args.test:
        print("Launching fifo test rom")
        rom = get_test_rom()
        rom = NesRom(rom=rom, name="fifo_testrom.nes")
        everdrive.load_game(rom)
    elif args.print_state:
        everdrive.print_state()


def to_string(data: bytearray):
    return "-".join(f"{e:02x}".upper() for e in data)


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
                self.port = Serial(port=port.device, baudrate=BAUD_RATE, timeout=0.5)
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
        logger.debug(f"Transmitting {len(data)}: {data[:48].hex()}")
        while length > 0:
            block = BLOCK_SIZE
            if block > length:
                block = length
            chunk = data[offset : offset + block]
            self.port.write(chunk)
            length -= block
            offset += block

    def receive_data(self, length: int) -> bytearray:
        data = self.port.read(length)
        data = bytearray(data)
        logger.debug(f"Received {len(data)}: {data[:48].hex()}")
        return data

    def transmit_command(self, command: int):
        cmd = bytearray(4)
        cmd[0] = ord("+")
        cmd[1] = ord("+") ^ 0xFF
        cmd[2] = command
        cmd[3] = command ^ 0xFF
        self.transmit_data(cmd)
        logger.debug(f"Transmitting command: {cmd.hex()}")

    def memory_read(self, address: int, length: int):
        logger.debug(f"Reading {length} from 0x{address:08x}")
        self.transmit_command(CMD_MEM_RD)
        self.transmit_32(address)
        self.transmit_32(length)
        self.transmit_8(0)
        return self.receive_data(length)

    def memory_write(self, address: int, data: bytearray):
        length = len(data)
        logger.debug(f"Writing {length} to {address:08x}")
        self.transmit_command(CMD_MEM_WR)
        self.transmit_32(address)
        self.transmit_32(length)
        self.transmit_8(0)
        self.transmit_data(data)

    def receive_8(self):
        result = self.receive_data(1).pop()
        logger.debug(f"receive_8: {result:02x}")
        return result

    def receive_16(self):
        result = self.receive_data(2)
        result = result[1] << 8 | result[0]
        logger.debug(f"receive_16: {result:04x}")
        return result

    def receive_32(self):
        result = self.receive_data(4)
        result = result[0] | (result[1] << 8) | (result[2] << 16) | (result[3] << 24)
        logger.debug(f"receive_16: {result:08x}")
        return result

    def transmit_32(self, data: int):
        logger.debug(f"transmit_32: {data:08x}")
        self.transmit_data(bytearray(data.to_bytes(length=4, byteorder="little")))

    def transmit_16(self, data: int):
        logger.debug(f"transmit_16: {data:04x}")
        self.transmit_data(bytearray(data.to_bytes(length=2, byteorder="little")))

    def transmit_8(self, data: int):
        logger.debug(f"transmit_8 {data:02x}")
        self.transmit_data(bytearray([data & 0xFF]))

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
        logger.debug(f"string fifo: {length.hex()} {data.hex()}")
        self.write_fifo(length)
        self.write_fifo(data)

    def transmit_string(self, message: str):
        length = bytearray(len(message).to_bytes(2, "little"))
        data = bytearray(message.encode())
        logger.debug(f"string: {length.hex()} {data.hex()}")
        self.transmit_data(length)
        self.transmit_data(data)

    def command(self, command):
        data = bytearray(2)
        data[0] = ord("*")
        data[1] = command
        logger.debug(f"command: {data.hex()}")
        self.write_fifo(data)

    def load_game(self, rom: NesRom):
        logger.debug(f"Sending command to select game")
        self.command(CMD_SEL_GAME)

        rom_name = f"USB:{rom.name}"
        self.transmit_string_fifo(rom_name)
        logger.debug(f"Received: {self.receive_8()}")

        logger.debug(f"writing rom id to fifo")
        rom_id = rom.get_rom_id()

        logger.debug(f"rom id: {'-'.join(f'{b:02x}'.upper() for b in rom_id)}")
        self.write_fifo(rom_id)
        logger.debug(f"Received: {self.receive_8()}")

        logger.debug(f"getting 2 bytes for map_idx")
        map_idx = self.receive_16()

        logger.debug(f"Running the game:  {map_idx}")
        self.command(CMD_RUN_GAME)
        logger.debug(f"Received: {self.receive_8()}")
        self.memory_write(rom.ADDR_PRG, rom.prg)
        self.memory_write(rom.ADDR_CHR, rom.chr)
        self.map_load_sdc(map_idx)

    def fpg_init_direct(self):
        """
        Unused.  Setup as a test while troubleshooting.
        """
        fpg = bytearray(open("004.RBF", "rb").read())
        self.transmit_command(CMD_FPG_USB)
        self.transmit_32(len(fpg))
        self.transmit_data_ack(fpg)
        self.check_status()

    def file_info(self, path: str):
        logger.debug(f"Requesting file info")
        self.transmit_command(CMD_F_FINFO)
        self.transmit_string(path)
        response = self.receive_8()
        if response:
            raise RuntimeError(f"File access error: {response:02x}")
        return self.receive_file_info()

    def receive_file_info(self) -> FileInfo:
        logger.debug(f"Receiving file info")
        fileinfo = FileInfo()
        fileinfo.size = self.receive_32()
        fileinfo.date = self.receive_16()
        fileinfo.time = self.receive_16()
        fileinfo.attrib = self.receive_8()
        fileinfo.name = self.receive_string()
        return fileinfo

    def receive_string(self):
        length = self.receive_16()
        logger.debug(f"Receiving String of {length} length")
        data = self.receive_data(length)
        return bytes(data).decode()

    def fpg_init(self, path: str):
        logger.debug(f"Initializing FPG: {path}")
        fileinfo = self.file_info(path)
        self.open_file(path, FAT_READ)
        self.transmit_command(CMD_FPG_SDC)
        self.transmit_32(fileinfo.size)
        self.transmit_8(0)
        self.check_status()

    def check_status(self):
        logger.debug(f"Checking Status")
        response = self.get_status()
        if response:
            raise RuntimeError(f"Operation error: {response:02x}")

    def get_status(self):
        self.transmit_command(CMD_STATUS)
        response = self.receive_16()
        if (response & 0xFF00) != 0xA500:
            raise RuntimeError(f"Unexpected response: {response:04x}")
        return response & 0xFF

    def transmit_data_ack(self, data):
        """
        unused.  set up along fpg_init_direct
        """
        length = len(data)
        offset = 0
        while length > 0:
            response = self.receive_8()
            if response:
                raise RuntimeError(f"Tx ack: {response:02x}")
            block = ACK_BLOCK_SIZE
            if block > length:
                block = length
            self.transmit_data(data[offset : offset + block])
            length -= block
            offset += block

    def map_load_sdc(self, map_id: int):
        map_path = "EDN8/MAPS/"
        self.open_file("EDN8/MAPROUT.BIN", FAT_READ)
        map_data = self.read_file(4096)
        self.close_file()

        map_pkg = map_data[map_id]
        if map_pkg < 100:
            map_path += "0"
        if map_pkg < 10:
            map_path += "0"
        map_path = f"{map_path}{map_pkg}.RBF"
        logger.debug(f"int mapper: {map_path}")
        self.fpg_init(map_path)

    def open_file(self, path: str, mode: int):
        logger.debug(f"Opening: {path}")
        self.transmit_command(CMD_F_FOPN)
        logger.debug(f"File open command: {CMD_F_FOPN}")
        self.transmit_8(mode)
        logger.debug(f"File open mode: {mode}")
        self.transmit_string(path)
        logger.debug(f"File open path: {path}")
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
            data[offset : offset + block] = self.receive_data(block)
            offset += block
            length -= block
        return data


class NesRom:
    ROM_TYPE_NES = 0
    MIR_HOR = "H"
    MIR_VER = "V"
    MIR_4SC = "4"
    MIR_1SC = "1"
    MAX_ID_CALC_LEN = 0x100000
    ADDR_PRG = 0x0000000
    ADDR_CHR = 0x0800000

    def __init__(self, rom: bytearray, name: str):
        self.rom_type = self.ROM_TYPE_NES
        self.name = name
        self.rom = rom
        self.size = len(self.rom)
        self.ines = self.rom[:32]
        self.nes = self.ines[0:3] == bytearray(b"NES")
        if not self.nes:
            raise RuntimeError(f"This script only supports nes: {self.ines[0:3]}")
        self.dat_base = 16
        self.prg_size = self.rom[4] * 1024 * 16
        self.chr_size = self.rom[5] * 1024 * 8
        self.srm_size = 8192
        if not self.prg_size:
            self.prg_size = 0x400000
        self.mapper = (self.rom[6] >> 4) | (self.rom[7] & 0xF0)
        self.mirroring = self.MIR_VER if self.rom[6] & 1 else self.MIR_HOR
        self.bat_ram = bool((self.rom[6] & 2))
        if self.rom[6] & 8:
            self.mirroring = self.MIR_4SC
        self.crc = zlib.crc32(self.rom[self.dat_base :])
        if self.mapper == 255:
            raise RuntimeError(f"OS mapper not yet supported")
        self.prg = self.rom[16 : 16 + self.prg_size]
        self.chr = self.rom[16 + self.prg_size : 16 + self.prg_size + self.chr_size]

        logger.debug(f"{self.mapper=}")
        logger.debug(f"{self.prg_size=}")
        logger.debug(f"{self.chr_size=}")
        logger.debug(f"{self.srm_size=}")
        logger.debug(f"{self.mirroring=}")
        logger.debug(f"{self.bat_ram=}")
        logger.debug(f"{self.crc=:08x}")

    @classmethod
    def from_file(cls, file):
        name = pathlib.Path(file).name
        rom = bytearray(bytes(open(file, "rb").read()))
        return cls(rom=rom, name=name)

    def get_rom_id(self):
        logger.debug("Getting rom ID")
        offset = len(self.ines)
        data = bytearray(offset + 12)
        data[:offset] = self.ines
        data[offset : offset + 4] = bytearray(self.size.to_bytes(4, "little"))
        data[offset + 4 : offset + 8] = bytearray(self.crc.to_bytes(4, "little"))
        data[offset + 8 :] = bytearray((16).to_bytes(4, "little"))
        return data


def apply_ips_patch(rom: bytearray, patch: bytes, sha1sum: str = "") -> bytearray:
    ptr = 5
    while ptr < len(patch):
        offset = int.from_bytes(patch[ptr : ptr + 3], "big")
        size = int.from_bytes(patch[ptr + 3 : ptr + 5], "big")
        ptr += 5
        if size:
            rom[offset : offset + size] = patch[ptr : ptr + size]
            ptr += size
        else:
            data = patch[ptr + 2 : ptr + 3] * int.from_bytes(
                patch[ptr : ptr + 2], "big"
            )
            rom[offset : offset + len(data)] = data
            ptr += 3
        if patch[ptr:] == b"EOF":
            ptr += 3
    if sha1sum and (new_sha1sum := hashlib.sha1(rom).digest().hex()) != sha1sum.lower():
        print(f"Invalid sha1sum: {new_sha1sum}", file=sys.stderr)
        sys.exit(1)
    elif sha1sum:
        print("Valid sha1sum")
    return rom


def get_test_rom() -> bytearray:
    rom = bytearray(TEST_ROM_LEN)
    patch = base64.b85decode(fifo_testrom)
    return apply_ips_patch(rom, patch, TEST_ROM_SHA1SUM)


def open_rom_with_patch(rom_file: str, patch_file: str, sha1sum: str = "") -> bytearray:
    patch = open(patch_file, "rb").read()
    if patch[:5] != b"PATCH":
        print(f"{patch_file} doesn't look like a patch", file=sys.stderr)
        sys.exit(1)
    rom = bytearray(open(rom_file, "rb").read())
    return apply_ips_patch(rom, patch, sha1sum)


def count_bytes(everdrive: Everdrive):
    counter = 0
    while True:
        byte_ = everdrive.receive_data(1)
        if not byte_:
            break
        counter += 1
    print(counter)


def send_fifo(everdrive: Everdrive, *numbers):
    payload = bytearray(n & 0xFF for n in numbers)
    everdrive.write_fifo(payload)


fifo_testrom = (
    b"P(f5fNB{r;00&M*QyKyR0{{RJ1A3(m&;+Fp@H6HYsVj}}KuQ0N@Ia{|jqpH8|BdiKr45bnK&1|i@Ia*u"
    b"qz<MH@CJ?WK+4eih`|5Q^<d@~t?@vG3Sj0Jt?)pF3t;9KsQ`r)g%+*xK*>SS46X1$<`vNL<`zs;fMBTs"
    b"jTS(K1xk$;K&=))N+t!6_@xC%MFu4Wg#~DZ24F~vNSH|G0;vIo2dN;91|X@3jRqj152^o+2O!E2`l%p|"
    b"1|X@SjRqj1lAwVg(1E27jRzp55RC^QqMD$AAkcxO5se2Rr4o$?Af*$H2Oy;sjRzp9A&mwgsUeL9Aflt7"
    b"fgsR<r3xV9fvF*l1|X@SjRqj1v7mt<(1E23Amf3lB8>(hsUeL9AfmsZfgsR<r4}ILfu$87<AJFnjRqj8"
    b"p^XM0qRpUzAkcxO7a-$-rU<=+fsF<ry@-L01|X^MjRzp53Gf)HAdLnfrU|`^ff#9r7-b2K1|X^NjRzp9"
    b"0F4D8jRhd7h>ZXssSb?+ARuUfXsBqaXh0w#AtIq6p&<YO2nYxWAX8;-WFRE}AY*TJZge0d{~%IjVPqgA"
    b"G%#i{JtY4iQe|OeAS5&}W-vV@{~&B-ZYXheWp!mKJtY4iB>#p0gaM!cu>i^c@CJ<sAjr`4U`R?zN=l6f"
    b"AZRHMjRzoLr3lbPr3EPh@Ce2U5Co|Pg$bnvDFN^d<_V<<$p_E`sQ`rur3vsMrU|75DG2Zg_71fUDG!wn"
    b"r3EPj@CeopwGJr{l@3f>f~5s12=EBT2oMCR1BD2s1t|pZ4CV->2+0J{1gQXp2&EAU3JMAZ5`_+>6AB6n"
    b"3I!B}4W$nX3JMAZ5QPk-1u1~=1*Hfemx8GPg$Jbv@cc~jfdGI!fJA^yfC{R;kAj5&y^w;10c-#Oc-W#q"
    b"ju$|p|C;EI03eP5AdV0~ECL`b0w56kij@GJ00Er<0-XQ@od5)#00o@@2Au#0=+NdY0w56ksUVF8AgKV2"
    b"1|XsUssD`!An4HgsUeL9AgKV21|XsUssD`!An4HgsUnRAAgKV21|XsUssD`!An4HgsUwXBAgKV21|Xuq"
    b"ssD`!Aj;7CsXvVdAgKV21|XsUy;+0F|L_Nm2O#K7K7*-<jQ}929*qGYO!9#bFfcF=FfcF=FfcF=FfcF="
    b"FfcF=FfcF=FfcF=FfcIx0DuYs1&DyAf`fq`GdDjwGadjQGdDjwGadj891IK$3?2Xs91IK$3?2X;GY1YF"
    b"I6nX$GY1YFI6nX$GXo9-GadjQGXo9-Gadj24i+Xq1_l5I4i+Xq1_l5>Fg^nVGadjxFg^nVGadjQGcZ0g"
    b"GadjQGcZ0gGadjxBLfBo3=9B2BLfBo3=9AsGcz7DGadjQGcz7DGadjQGcz9pGadjQGcz9pGadjQGc!Lk"
    b"Gcy1lGc!LkGcy2wGc!IjGkySmGc!IjGkyRcGchnQF&+RPGchnQF&+SZGcz+YGkySmGcz+YGkySnF)%zZ"
    b"F@FGmF)%zZF@FGmF)%zZFmM2WF)%zZFmM2ZAONly7#J8B02lxm7#J8B02lylY)AkA0001NY)AkA0000e"
    b"e0(T;d?)}Ye0(T;d?)}AJa9N1cn|;(Ja9N1cn|=_&Kx*!=EeZV&Kx*!=EeXxWN<ocW;y^kWN<ocW;y^E"
    b"7!Uve0000O7!Uve0000OFfcGMFc<(BFfcGMFc<(B3=9km3>W|y3=9km3>W|aY&iZnYybcNY&iZnYybcN"
    b"7#MyS7ytkO7#MyS7yyFQ01y}$2mk;8000;m2mk;806YMK>i_{f0D|=Z0vH$og8c&i7#IKy3>+9ZFfafN"
    b"3>+9ZFfaf-W^R6VW;_5qW^R6VW;_5GI2afh7(4(NI2afh7(4(xW)2)UaDD(hW)2)UaDD(hW(FJvW;_5q"
    b"W(FJvW;_5494t(J3=9Aa94t(J3=9B%V0;D!W;_6XV0;D!W;_5qW?+0~W;_5qW?+0~W;_6XMg|NF7#IM4"
    b"Mg|NF7#ILNW@bEQW;_5qW@bEQW;_5qW@bJHW;_5qW@bJHW;_4@7#IK;7ytkO7#IK;7ytkO7#IK;7zh9W"
    b"7#IK;7zh9i7%*Tk7z_Xm7%*Tk7z_Xa06YLZ0000006YLZ0000m7z_ps7%%`Z7z_ps7%%`lW(Eux02lx~"
    b"W(Eux02lx~W^Qg^VmtsmW^Qg^VmtsmW@dh7W@Z39W@dh7W@Z5VW@db5X8ZvBW@db5X8Zs?W@2DqVmtso"
    b"W@2DqVmtu+W@ct)X8ZvBW@ct)X8ZvDVqkb+V*UXBVqkb+V*UXBVqkb+VBi4$Vqkb+VBi3J#=y?T#(V&L"
    b"#=y?T#(V%~W@dh7W@Z3pW@dh7W@Z397#J8B7(4(x7#J8B7(4(z3=9kmOgI2O3=9kmOgI4cW^8zDX7&K~"
    b"W^8zDX7&JhFfcGMGJXJfFfcGMGJXKY?*7)s#>N1~?*7)s#>N0<W_EsVW@Z3pW_EsVW@Z39W@ct)W;_5q"
    b"W@ct)W;_7=W@da~VDJF^W@da~VDJDuW@ct)Y&rluW@ct)Y&rn^W@db5X669=W@db5X667sVqiQ5MtlH1"
    b"VqiQ5MtlH%S{N7@7(4)eS{N7@7(4)GW@ct)W;_69W@ct)W;_69W@ct?JQx6GW@ct?JQx7R#>UqEY(xOY"
    b"#>UqEY(xNNW;_@?W@Z3pW;_@?W@Z3pW^Ozf7#IL%W^Ozf7#IM4P8>LJVtxRAP8>LJVtxQTFfcGMFgyS}"
    b"FfcGMFgyS-FgO?-3=9A;FgO?-3=9A~3=9km3_Jil3=9km3_Ji3IBWm_0000GIBWoh1^@wm0EP|#4t@YI"
    b"I2;TB0000mI2;TBh9Uv2JO(~yJ^%m!JO(~yJ^)}~d}d~5d;nlzd}d~5d;kCdJYryCJOBUyJYryCJOBm;"
    b"K4xZSJ^%&=K4xZSJ^%m!JZ64iJOBUyJZ64iJOB<D7(5slJOB<D7(5slJOBUyK4xY<20Q=&K4xY<20UP3"
    b"Y<6a5W&mJdY<6a5W&jufI2afhJOCH~I2afhJOB&;91IK$3^)t`91IK$3^-t5WNdhBW&mJdWNdhBW&k)C"
    b"7#J8BJODTt7#J8BJOBUy?AF%S)&Kwi?AF%S)&KwiTxMowW&i*HTxMowW&i*HJZ5HQJOBUyJZ5HQJOBUy"
    b"d}d~RU|;|Md}d~RU|;|MK4xY<1_l5CK4xY<1_l5CY<6H^U;qFBY<6H^U;qFBJYYNqJOBUyJYYNqJOD5-"
    b"d@wLD8~`vdd@wLD8~^|SW@ct)IsgCwW@ct)IsgCwW@ctQ7ytkOW@ctQ7ytkOMpjl<J^%m!Mpjl<J^%m!"
    b"W;_@?W&i*HW;_@?W&i*HW@bJH8~^|SW@bJH8~^|Sd>A+|d;kCdd>A+|d;lCUFkmn+8~_|JFkmn+8~}&V"
    b"0000G7yyUh05CWV3<eAgH~=^d3<eAgH~;_uGJZ?|00000GJZ?|002BfnW3ebLOeV|nW3ebLOcME5da-P"
    b"U~qVFU_bysU~qVFU_bx>e?A-t00000e?A-t0FTfB000pG0FUSZ000pG0FV#>{~j|pKRYuX03I_pKRYuX"
    b"01O-q3=9k&01O-q3=9k&03I_34jec?03I_34jec?03I^~4g)hD03I^~4g)hD00s^gCO-xS00s^gCO-xS"
    b"06#E30|PT206#E30|PT203I_iJ~J~O03I_iJ~J~O06!xG1_lfa06!xG1_lfa03I_l9y2o@03I_l9y2o@"
    b"03I_l9|JQU03I_l9|JQU03I_lKQl8k03I_lKQl8k0DdzwJ~K0Z0DdzwJ~K0Z03S0kFfcJ503S0kFfcJ5"
    b"0DdzwGcz-O0DdzwGcz-O0DmzsJTNhT0DmzsJTNhT0DmzsJTNeD0DmzsJTNeD0Fod8t{4~?7#IK;02mk;"
    b"7#IK;0BmeX000000BmeX0000004RKXD13Y<04RKXD13Y<01!NII2?Eo01!NII2?Eo0LIQ7IB@310LIQ7"
    b"IB@31061iDI&5Y-061iDI&5Y-02mk$0000002mk$0000002nYZFfcF}02nYZFfcF}02mAm3=9ky02mAm"
    b"3=9ky003+_{y1y^003+_{y1y^000;mei#@4000;mei#@4lGFeY7#Iiu000007#Iiu0000y0Fvtf0XzVb"
    b"^#B4G7yy#}0{$2n01ONq7&tI601ONq7&tI606b=Hes*R&06b=Hes*R&02nwJ7#J8l02nwJ7#J8l06b<6"
    b"95`@(06b<695`@(06b;}90q1Q06b;}90q1Q01O-~OnwXu01O-~OnwXu0DfS61_ow40DfS61_ow406b=3"
    b"d}d}m06b=3d}d}m0DeXW3=9|;0DeXW3=9|;06b=9JZ5G*06b=9JZ5G*06b=9J_cqy06b=9J_cqy000;m"
    b"02mkm000;m02mkm000;m02mku000;m02mku01Ox~U@#aA01Ox~U@#aA0000y06YKy0000y06YKy05BK~"
    b"1`HT505BK~1`HT506b;}3>W|y06b;}3>W|y06b=HZeU_O06b=HZeU_O06b=9er9H706b=9er9H70Q_cV"
    b"d}e0+0Q_cVd}e0+06u17U|?cA06u17U|?cA0Q_cVW@cvm0Q_cVW@cvm0RCcNcwl1w0RCcNcwl1w0RCcN"
    b"cwk`Q0RCcNcwk`Q0DQ*4&c?=k0DQ*4&c?=k0A^-per9H70A^-per9H706Z8N7#J8l06Z8N7#J8l06q*1"
    b"3=B*-06q*13=B*-0QP2Vcx-0&0QP2Vcx-0&0C+GkFfcNH0C+GkFfcNH0LJeA*2c!h0LJeA*2c!h0A^-("
    b"er{%F0A^-(er{%F06b=9W@ctQ06b=9W@ctQ0Q_cVd|+Vk0Q_cVd|+Vk06b=9W@c<U06b=9W@c<U0Q_cV"
    b"d}e0m0Q_cVd}e0m06t=1JO)O506t=1JO)O50Df8+7#J8l0Df8+7#J8l0A^-pW@ctQ0A^-pW@ctQ0A^-p"
    b"W^Ozf0A^-pW^Ozf0LI3~*8Xfn0LI3~*8Xfn0A^-97(8ZX0A^-97(8ZX0A^-xJQx@l0A^-xJQx@l0Dev!"
    b"IB;Tq0Dev!IB;Tq06Z`-FfcGY06Z`-FfcGY05C8(7#s`?05C8(7#s`?06Yu~3=9lB06Yu~3=9lB01!BA"
    b"0000001!BA0G0*-0e%3M4gd~*05CWl3;+NC05CWl3;>oQ0j)d+K4v}u002A&K4v}uU|@V^W@dZ<U|@V^"
    b"W@dZ<002B<U}8J~002B<U}8J~1_nN6W@bJB1_nN6W@bJB002B@eqcNR002B@eqcNR4j33b7#KVN4j33b"
    b"7#KVN002H_W<CZy002H_W<CZyU|?)^W@cspU|?)^W@csp7yvjJ7#KVN7yvjJ7#KVN3;-Mq3=9l73;-Mq"
    b"3=9l7U|?iycx+|>U|?iycx+|>I2afh7#KVNI2afh7#KVN008XP*4EYl008XP*4EYl003NOW@csp003NO"
    b"W@csp002B@W@bD9002B@W@bD9004YuW_(~^004YuW_(~^002H_W<CZ6002H_W<CZ6003-uU|?VX003-u"
    b"U|?VX002B-JO(@f002B-JO(@fFfe>DFfbedFfe>DFfbed003rYW@b77003rYW@b77003rYW;_@G003rY"
    b"W;_@G002f-R#rX$002f-R#rX$003q@7(8YG003q@7(8YG003rYJ_Z~B003rYJ_Z~B004X#I52zw004X#"
    b"I52zw9566oFfbed9566oFfbedm(TzJ01y}em*4;}I1CI13=B8`I1CI13=B8`001(6OaK4?001(6OaK4?"
    b"JVKeFrI|uJJVKeFrI|uJ0G|;69YA1kcyM4q06<`HcyM4q004hJ90&ja004hJ90&lP&;S4c5dQ$5=l}o!"
    b"5dTF_Mg"
)


if __name__ == "__main__":
    main()
