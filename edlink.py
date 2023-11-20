import os
import logging
import re
import zlib

from serial import Serial

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

STATE_LENGTH = 0x100

ACK_BLOCK_SIZE = 1024

CMD_STATUS = 0x10
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

    def memory_write(self, address: int, data: bytearray):
        length = len(data)
        logger.debug(f"Attempting to write {length} bytes to 0x{address:08x}")
        self.transmit_command(CMD_MEM_WR)
        self.transmit_32(address)
        self.transmit_32(length)
        self.transmit_8(0)
        self.transmit_data(data)
    
    def receive_8(self):
        return self.receive_data(1).pop()
    
    def receive_16(self):
        result = self.receive_data(2)
        return result[1] << 8 | result[0]

    def print_state(self):
        state = self.memory_read(
            address=ADDR_SSR,
            length=STATE_LENGTH,
        )
        for i in range(0, STATE_LENGTH, 16):
            print(f"{to_string(state[i:i+8])}   {to_string(state[i+8:i+16])}")

    def write_fifo(self, data: bytearray):
        self.memory_write(ADDR_FIFO, data)



        # void txString(string str)
        # {
        #     byte[] bytes = Encoding.ASCII.GetBytes(str);
        #     UInt16 str_len = (UInt16)bytes.Length;
        #     edio.fifoWR(BitConverter.GetBytes(str_len), 0, 2);
        #     edio.fifoWR(bytes, 0, bytes.Length);
        # }


        # void cmd(char cmd)
        # {
        #     byte[] buff = new byte[2];
        #     buff[0] = (byte)'*';
        #     buff[1] = (byte)cmd;
        #     edio.fifoWR(buff, 0, buff.Length);
        # }


    #    public void loadGame_old(NesRom rom, string map_path)
    #     {

    #         int resp;
   
    #         byte[] id_bin = rom.getRomID();
    #         byte[] prg = rom.PrgData;
    #         byte[] chr = rom.ChrData;

    #         cmd(cmd_sel_game);
    #         txString("USB:" + Path.GetFileName(rom.Name));
    #         resp = edio.rx8();//system ready to receive id
    #         edio.fifoWR(id_bin, 0, id_bin.Length);
    #         resp = edio.rx8();
    #         if (resp != 0)
    #         {
    #             throw new Exception("Game select error 0x: " + resp.ToString("X2"));
    #         }
    #         int map_idx = edio.rx16();

    #         if (map_idx != rom.Mapper)
    #         {
    #             Console.WriteLine("map reloc: " + map_idx);
    #         }
    #         if (map_path == null)
    #         {
    #             map_path = getTestMapper(map_idx);
    #         }

    #         cmd(cmd_run_game);
    #         edio.rx8();//exec

    #         edio.memWR(rom.PrgAddr, prg, 0, prg.Length);
    #         edio.memWR(rom.ChrAddr, chr, 0, chr.Length);

    #         if (map_path == null)
    #         {
    #             mapLoadSDC(map_idx, null);
    #         }
    #         else
    #         {
    #             Console.WriteLine("ext mapper: " + map_path);
    #             edio.fpgInit(File.ReadAllBytes(map_path), null);
    #         }
            
    #     }

        # public void fpgInit(byte[] data, MapConfig cfg)
        # {
        #     //if (cfg != null) fpgInitCfg(cfg);
        #     txCMD(CMD_FPG_USB);
        #     tx32(data.Length);
        #     txDataACK(data, 0, data.Length);
        #     checkStatus();
        #     if (cfg != null) memWR(ADDR_CFG, cfg.getBinary(), 0, cfg.getBinary().Length);
        # }



        # void checkStatus()
        # {
        #     int resp = getStatus();
        #     if (resp != 0) throw new Exception("operation error: " + resp.ToString("X2"));
        # }

        # public int getStatus()
        # {
        #     int resp;
        #     txCMD(CMD_STATUS);
        #     resp = rx16();
        #     if ((resp & 0xff00) != 0xA500) throw new Exception("unexpected status response (" + resp.ToString("X4") + ")");
        #     return resp & 0xff;
        # }




        # void txDataACK(byte[] buff, int offset, int len)
        # {
        #     while (len > 0)
        #     {
        #         int resp = rx8();
        #         if (resp != 0) throw new Exception("tx ack: " + resp.ToString("X2"));

        #         int block = ACK_BLOCK_SIZE;
        #         if (block > len) block = len;

        #         txData(buff, offset, block);

        #         len -= block;
        #         offset += block;

        #     }
        # }

        # void mapLoadSDC(int map_id, MapConfig cfg)
        # {
        #     string map_path = "EDN8/MAPS/";
        #     int map_pkg;
        #     byte[] map_rout = new byte[4096];

        #     edio.fileOpen("EDN8/MAPROUT.BIN", Edio.FAT_READ);
        #     edio.fileRead(map_rout, 0, map_rout.Length);
        #     edio.fileClose();

        #     map_pkg = map_rout[map_id];
        #     if (map_pkg == 0xff && map_id != 0xff)
        #     {
                
        #         cfg = new MapConfig();
        #         cfg.map_idx = 255;
        #         cfg.Ctrl = MapConfig.ctrl_unlock;
        #         edio.fpgInit("EDN8/MAPS/255.RBF", cfg);
        #         throw new Exception("Unsupported mapper: " + map_id);
        #     }

        #     if (map_pkg < 100) map_path += "0";
        #     if (map_pkg < 10) map_path += "0";
        #     map_path += map_pkg + ".RBF";

        #     Console.WriteLine("int mapper: " + map_path);
        #     edio.fpgInit(map_path, cfg);
        # }



        # public void fileOpen(string path, int mode)
        # {
        #     txCMD(CMD_F_FOPN);
        #     tx8(mode);
        #     txString(path);
        #     checkStatus();
        # }



        # public void fileClose()
        # {
        #     txCMD(CMD_F_FCLOSE);
        #     checkStatus();
        # }





        # public void fileRead(byte[] buff, int offset, int len)
        # {

        #     txCMD(CMD_F_FRD);
        #     tx32(len);


        #     while (len > 0)
        #     {
        #         int block = 4096;
        #         if (block > len) block = len;
        #         int resp = rx8();
        #         if (resp != 0) throw new Exception("file read error: " + resp.ToString("X2"));

        #         rxData(buff,  offset, block);
        #         offset += block;
        #         len -= block;

        #     }

        # }










# namespace edlink_n8
# {
#     class MapConfig
#     {

#         const int cfg_base = 32;

#         public const byte cfg_mir_h = 0;
#         public const byte cfg_mir_v = 1;
#         public const byte cfg_mir_4 = 2;
#         public const byte cfg_mir_1 = 3;
#         public const byte cfg_chr_ram = 4;
#         public const byte cfg_srm_off = 8;

#         public const byte ctrl_rst_delay = 0x01;
#         public const byte ctrl_ss_on = 0x02;
#         public const byte ctrl_ss_btn = 0x08;

#         public const byte ctrl_unlock = 0x80;

#         byte[] config = new byte[cfg_base + 16];

#         public MapConfig(byte[] bin)
#         {
#             Array.Copy(bin, 0, config, 0, config.Length);
#         }

#         public MapConfig()
#         {
#             map_idx = 255;
#             SSKey_load = 0xff;
#             SSKey_save = 0xff;
#             SSKey_menu = 0xff;
#         }

#         public MapConfig(NesRom rom)
#         {

#             map_idx = rom.Mapper;

#             if (rom.Mirroring == 'H') MapCfg |= cfg_mir_h;
#             if (rom.Mirroring == 'V') MapCfg |= cfg_mir_v;
#             if (rom.Mirroring == '4') MapCfg |= cfg_mir_4;
#             if (rom.ChrSize == 0) MapCfg |= cfg_chr_ram;

#             PrgSize = rom.PrgSize;
#             ChrSize = rom.ChrSize;
#             SrmSize = rom.SrmSize;

#             MasterVol = 8;
#             SSKey_menu = 0x14;//start + down
#             SSKey_save = 0xff;// 0x14;
#             SSKey_load = 0xff;// 0x18;//start + up

#         }


#         public void printFull()
#         {

#             Console.WriteLine("mappper....." + map_idx + " sub." + Submap);

#             Console.WriteLine("prg size...." + PrgSize / 1024 + "K");
#             string chr_type = (MapCfg & cfg_chr_ram) == 0 ? "" : "ram";
#             Console.WriteLine("chr size...." + ChrSize / 1024 + "K " + chr_type);
#             string stm_state = (MapCfg & cfg_srm_off) != 0 ? "srm off" : SrmSize < 1024 ? (SrmSize + "B ") : (SrmSize / 1024 + "K ");
#             Console.WriteLine("srm size...." + stm_state);

#             Console.WriteLine("master vol.." + MasterVol);

#             string mir = "?";
#             if ((MapCfg & 3) == cfg_mir_h) mir = "h";
#             if ((MapCfg & 3) == cfg_mir_v) mir = "v";
#             if ((MapCfg & 3) == cfg_mir_4) mir = "4";
#             if ((MapCfg & 3) == cfg_mir_1) mir = "1";
#             Console.WriteLine("mirroring..." + mir);
#             Console.WriteLine("cfg bits...." + Convert.ToString(MapCfg, 2).PadLeft(8, '0'));

#             Console.WriteLine("menu key....0x{0:X2}", SSKey_menu);
#             Console.WriteLine("save key....0x{0:X2}", SSKey_save);
#             Console.WriteLine("load key....0x{0:X2}", SSKey_load);
#             Console.WriteLine("rst delay..." + ((Ctrl & ctrl_rst_delay) != 0 ? "yes" : "no"));
#             Console.WriteLine("save state.." + ((Ctrl & ctrl_ss_on) != 0 ? "yes" : "no"));
#             Console.WriteLine("ss button..." + ((Ctrl & ctrl_ss_btn) != 0 ? "yes" : "no"));
#             Console.WriteLine("unlock......" + ((Ctrl & ctrl_unlock) != 0 ? "yes" : "no"));
#             Console.WriteLine("ctrl bits..." + Convert.ToString(Ctrl, 2).PadLeft(8, '0'));
#             print();

#         }

#         public void print()
#         {
#             Console.WriteLine("CFG0: " + BitConverter.ToString(config, cfg_base, 8));
#             Console.WriteLine("CFG1: " + BitConverter.ToString(config, cfg_base + 8, 8));
#         }

#         public byte[] getBinary()
#         {
#             return config;
#         }

#         byte getRomMask(int size)
#         {
#             byte msk = 0;
#             while ((8192 << msk) < size && msk < 15)
#             {
#                 msk++;
#             }
#             return (byte)(msk & 0x0F);
#         }

#         byte getSrmMask(int size)
#         {
#             byte msk = 0;
#             while ((128 << msk) < size && msk < 15)
#             {
#                 msk++;
#             }
#             return (byte)(msk & 0x0F);
#         }

#         public int map_idx
#         {
#             get
#             {
#                 return config[cfg_base + 0] | ((config[cfg_base + 2] & 0xf0) << 4);
#             }
#             set
#             {
#                 config[cfg_base + 0] = (byte)(value);
#                 config[cfg_base + 2] |= (byte)((value & 0xf00) >> 4);
#             }
#         }

#         public int PrgSize
#         {
#             get
#             {
#                 return 8192 << (config[cfg_base + 1] & 0x0f);
#             }
#             set
#             {
#                 config[cfg_base + 1] = (byte)((config[cfg_base + 1] & 0xf0) | getRomMask(value));
#             }
#         }

#         public int SrmSize
#         {
#             get
#             {
#                 return 128 << (config[cfg_base + 1] >> 4);
#             }
#             set
#             {
#                 config[cfg_base + 1] = (byte)((config[cfg_base + 1] & 0x0f) | getSrmMask(value) << 4);
#             }
#         }

#         public int ChrSize
#         {
#             get
#             {
#                 return 8192 << (config[cfg_base + 2] & 0x0f);
#             }
#             set
#             {
#                 config[cfg_base + 2] = (byte)((config[cfg_base + 2] & 0xf0) | getSrmMask(value));
#             }
#         }


#         public byte MasterVol
#         {
#             get { return config[cfg_base + 3]; }
#             set { config[cfg_base + 3] = value; }
#         }

#         public byte Submap
#         {
#             get { return (byte)(MapCfg >> 4); }
#             set { MapCfg = (byte)((MapCfg & ~0xf0)  | (value)); }
#         }

#         public byte MapCfg
#         {
#             get { return config[cfg_base + 4]; }
#             set { config[cfg_base + 4] = value; }
#         }


#         public byte SSKey_save
#         {
#             get { return config[cfg_base + 5]; }
#             set { config[cfg_base + 5] = value; }
#         }
#         public byte SSKey_load
#         {
#             get { return config[cfg_base + 6]; }
#             set { config[cfg_base + 6] = value; }
#         }

#         public byte Ctrl
#         {
#             get { return config[cfg_base + 7]; }
#             set { config[cfg_base + 7] = value; }
#         }

#         public byte SSKey_menu
#         {
#             get { return config[cfg_base + 8]; }
#             set { config[cfg_base + 8] = value; }
#         }



#     }
# }




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
