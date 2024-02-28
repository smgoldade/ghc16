/**
 * @author Steven Goldade
 * @date 2/27/2024
 */
#include <iostream>
#include <format>
#include <fstream>
#include <string>
#include <vector>
#include "types.h"

auto print_usage() -> void { std::cout << "Usage: ghc16 <input file> <offset>\n"; }

struct Hc16RawBinary {
    ~Hc16RawBinary() { delete[] data; }

    u64 length;
    u8* data;
};

auto read_hc16_file(const char* filename) -> Hc16RawBinary {
    std::ifstream hc16_file(filename, std::ios::binary | std::ios::ate);
    if(!hc16_file.is_open()) { return {0, nullptr}; }

    auto file_end = hc16_file.tellg();
    hc16_file.seekg(0, std::ios::beg);
    auto file_size = file_end - hc16_file.tellg();
    auto file_data = new u8[file_size];
    hc16_file.read(reinterpret_cast<char*>(file_data), file_size);
    hc16_file.close();

    static_assert(sizeof(std::streamoff) <= sizeof(u64), "streamoff is too large");
    return {static_cast<u64>(file_size), file_data};
}

struct Hc16Token {
    u32 address;
    std::string disassembly;
};

auto tokenize(const Hc16RawBinary& binary, const u32 base_address) -> std::vector<Hc16Token> {
    auto tokens = std::vector<Hc16Token>();

    for(auto offset = 0; offset < binary.length;) {
        auto const read_u8 = [&]() { return binary.data[offset++]; };
        auto const read_s8 = [&]() { return static_cast<s8>(binary.data[offset++]); };
        auto const read_u16 = [&]() { return static_cast<u16>((binary.data[offset++] << 8) + binary.data[offset++]); };
        auto const read_s16 = [&]() { return static_cast<s16>((binary.data[offset++] << 8) + binary.data[offset++]); };

        auto const op_addr = base_address + offset;
        auto const rel_addr = op_addr + 6;

        auto const register_mask = [&](const u8 op_code, const u8 y_mask, const u8 z_mask) {
            if((op_code & y_mask) == y_mask) { return 'Y'; }
            if((op_code & z_mask) == z_mask) { return 'Z'; }
            return 'X';
        };
        auto const emplace = [&](const std::string& mnemonic) { tokens.emplace_back(op_addr, mnemonic); };
        auto const emplace_imm8 = [&](const std::string& mnemonic) {
            auto const imm8 = read_u8();
            tokens.emplace_back(op_addr, std::format("{} #{:02X}h", mnemonic, imm8));
        };
        auto const emplace_imm16 = [&](const std::string& mnemonic) {
            auto const imm16 = read_u16();
            tokens.emplace_back(op_addr, std::format("{} #{:04X}h", mnemonic, imm16));
        };
        auto const emplace_ind8 = [&](const std::string& mnemonic, const u8 op_code, const u8 y_mask, const u8 z_mask) {
            auto const ind8 = read_u8();
            auto const reg = register_mask(op_code, y_mask, z_mask);
            tokens.emplace_back(op_addr, std::format("{} {:02X}h, {}", mnemonic, ind8, reg));
        };
        auto const emplace_ind16 = [&](const std::string& mnemonic, const u8 op_code, const u8 y_mask, const u8 z_mask) {
            auto const ind16 = read_u16();
            auto const reg = register_mask(op_code, y_mask, z_mask);
            tokens.emplace_back(op_addr, std::format("{} {:04X}h, {}", mnemonic, ind16, reg));
        };
        auto const emplace_eind = [&](const std::string& mnemonic, const u8 op_code, const u8 y_mask, const u8 z_mask) {
            auto const reg = register_mask(op_code, y_mask, z_mask);
            tokens.emplace_back(op_addr, std::format("{} E, {}", mnemonic, reg));
        };
        auto const emplace_rel8 = [&](const std::string& mnemonic) {
            auto const target_addr = rel_addr + read_s8();
            tokens.emplace_back(op_addr, std::format("{} {:04X}h", mnemonic, target_addr));
        };
        auto const emplace_rel16 = [&](const std::string& mnemonic) {
            auto const target_addr = rel_addr + read_s16();
            tokens.emplace_back(op_addr, std::format("{} {:04X}h", mnemonic, target_addr));
        };
        auto const emplace_mac8 = [&](const std::string& mnemonic) {
            auto const imm8 = read_u8();
            auto const x_index = static_cast<u8>((imm8 & 0xF0) >> 4);
            auto const y_index = static_cast<u8>(imm8 & 0xF);
            tokens.emplace_back(op_addr, std::format("{} {:01X}h,{:01X}h", mnemonic, x_index, y_index));
        };
        auto const emplace_ext = [&](const std::string& mnemonic) {
            auto const addr = read_u16();
            tokens.emplace_back(op_addr, std::format("{} {:04X}h", mnemonic, addr));
        };
        auto const emplace_ext20 = [&](const std::string& mnemonic) {
            auto const ext20 = ((read_u8() & 0xF) << 16) + read_u16();
            tokens.emplace_back(op_addr, std::format("{} {:06X}h", mnemonic, ext20));
        };
        auto const emplace_ind20 = [&](const std::string& mnemonic, const u8 op_code, const u8 y_mask, const u8 z_mask) {
            auto const ind20 = ((read_u8() & 0xF) << 16) + read_u16();
            auto const reg = register_mask(op_code, y_mask, z_mask);
            tokens.emplace_back(op_addr, std::format("{} {:06X}h, {}", mnemonic, ind20, reg));
        };
        auto const emplace_mext = [&](const std::string& mnemonic) {
            auto const mask = read_u8();
            auto const addr = read_u16();
            tokens.emplace_back(op_addr, std::format("{} {:04X}h, #{:02X}h", mnemonic, addr, mask));
        };
        auto const emplace_mextrel = [&](const std::string& mnemonic) {
            auto const mask = read_u8();
            auto const addr = read_u16();
            auto const target_addr = rel_addr + read_s16();
            tokens.emplace_back(op_addr, std::format("{} {:04X}h, #{:02X}h, {:04X}h", mnemonic, addr, mask, target_addr));
        };
        auto const emplace_m8ind8rel8 = [&](const std::string& mnemonic, const u8 op_code, const u8 y_mask, const u8 z_mask) {
            auto const mask = read_u8();
            auto const ind8 = read_u8();
            auto const target_addr = rel_addr + read_s8();
            auto const reg = register_mask(op_code, y_mask, z_mask);
            tokens.emplace_back(op_addr, std::format("{} {:02X}h, {}, #{:02X}h, {:04X}h", mnemonic, ind8, reg, mask, target_addr));
        };
        auto const emplace_m8ind8 = [&](const std::string& mnemonic, const u8 op_code, const u8 y_mask, const u8 z_mask) {
            auto const mask = read_u8();
            auto const ind8 = read_u8();
            auto const reg = register_mask(op_code, y_mask, z_mask);
            tokens.emplace_back(op_addr, std::format("{} {:02X}h, {}, #{:02X}h", mnemonic, ind8, reg, mask));
        };
        auto const emplace_m8ind16 = [&](const std::string& mnemonic, const u8 op_code, const u8 y_mask, const u8 z_mask) {
            auto const mask = read_u8();
            auto const ind16 = read_u16();
            auto const reg = register_mask(op_code, y_mask, z_mask);
            tokens.emplace_back(op_addr, std::format("{} {:04X}h, {}, #{:02X}h", mnemonic, ind16, reg, mask));
        };
        auto const emplace_m16ind16 = [&](const std::string& mnemonic, const u8 op_code, const u8 y_mask, const u8 z_mask) {
            auto const mask = read_u16();
            auto const ind16 = read_u16();
            auto const reg = register_mask(op_code, y_mask, z_mask);
            tokens.emplace_back(op_addr, std::format("{} {:04X}h, {}, #{:04X}h", mnemonic, ind16, reg, mask));
        };
        auto const emplace_m8ind16rel16 = [&](const std::string& mnemonic, const u8 op_code, const u8 y_mask, const u8 z_mask) {
            auto const mask = read_u8();
            auto const ind16 = read_u16();
            auto const target_address = rel_addr + read_s16();
            auto const reg = register_mask(op_code, y_mask, z_mask);
            tokens.emplace_back(op_addr, std::format("{} {:04X}h, {}, #{:02X}h, {:04X}h", mnemonic, ind16, reg, mask, target_address));
        };
        auto const emplace_ixpext = [&](const std::string& mnemonic) {
            auto const off8 = read_u8();
            auto const addr = read_u16();
            tokens.emplace_back(op_addr, std::format("{} {:02X}h, X, {:04X}h", mnemonic, off8, addr));
        };
        auto const emplace_extixp = [&](const std::string& mnemonic) {
            auto const off8 = read_u8();
            auto const addr = read_u16();
            tokens.emplace_back(op_addr, std::format("{} {:04X}h, {:02X}h, X", mnemonic, addr, off8));
        };
        auto const emplace_extext = [&](const std::string& mnemonic) {
            auto const addr1 = read_u16();
            auto const addr2 = read_u16();
            tokens.emplace_back(op_addr, std::format("{} {:04X}h, {:04X}h, X", mnemonic, addr1, addr2));
        };

        switch(auto const op_code = read_u8()) {
            case 0x00:
            case 0x10:
            case 0x20: {
                emplace_ind8("com", op_code, 0x10, 0x20);
                break;
            }
            case 0x01:
            case 0x11:
            case 0x21: {
                emplace_ind8("dec", op_code, 0x10, 0x20);
                break;
            }
            case 0x02:
            case 0x12:
            case 0x22: {
                emplace_ind8("neg", op_code, 0x10, 0x20);
                break;
            }
            case 0x03:
            case 0x13:
            case 0x23: {
                emplace_ind8("inc", op_code, 0x10, 0x20);
                break;
            }
            case 0x04:
            case 0x14:
            case 0x24: {
                emplace_ind8("asl", op_code, 0x10, 0x20);
                break;
            }
            case 0x05:
            case 0x15:
            case 0x25: {
                emplace_ind8("clr", op_code, 0x10, 0x20);
                break;
            }
            case 0x06:
            case 0x16:
            case 0x26: {
                emplace_ind8("tst", op_code, 0x10, 0x20);
                break;
            }
            case 0x08:
            case 0x18:
            case 0x28: {
                emplace_m8ind16("bclr", op_code, 0x10, 0x20);
                break;
            }
            case 0x09:
            case 0x19:
            case 0x29: {
                emplace_m8ind16("bset", op_code, 0x10, 0x20);
                break;
            }
            case 0x0A:
            case 0x1A:
            case 0x2A: {
                emplace_m8ind16rel16("brclr", op_code, 0x10, 0x20);
                break;
            }
            case 0x0B:
            case 0x1B:
            case 0x2B: {
                emplace_m8ind16rel16("brset", op_code, 0x10, 0x20);
                break;
            }
            case 0x0C:
            case 0x1C:
            case 0x2C: {
                emplace_ind8("rol", op_code, 0x10, 0x20);
                break;
            }
            case 0x0D:
            case 0x1D:
            case 0x2D: {
                emplace_ind8("asr", op_code, 0x10, 0x20);
                break;
            }
            case 0x0E:
            case 0x1E:
            case 0x2E: {
                emplace_ind8("ror", op_code, 0x10, 0x20);
                break;
            }
            case 0x0F:
            case 0x1F:
            case 0x2F: {
                emplace_ind8("lsr", op_code, 0x10, 0x20);
                break;
            }
            case 0x17: {
                switch(auto const op_code2 = read_u8()) {
                    case 0x00:
                    case 0x10:
                    case 0x20: {
                        emplace_ind16("com", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x01:
                    case 0x11:
                    case 0x21: {
                        emplace_ind16("dec", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x02:
                    case 0x12:
                    case 0x22: {
                        emplace_ind16("neg", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x03:
                    case 0x13:
                    case 0x23: {
                        emplace_ind16("inc", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x04:
                    case 0x14:
                    case 0x24: {
                        emplace_ind16("asl", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x05:
                    case 0x15:
                    case 0x25: {
                        emplace_ind16("clr", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x06:
                    case 0x16:
                    case 0x26: {
                        emplace_ind16("tst", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x08:
                    case 0x18:
                    case 0x28: {
                        emplace_m8ind8("bclr", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x09:
                    case 0x19:
                    case 0x29: {
                        emplace_m8ind8("bset", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x0C:
                    case 0x1C:
                    case 0x2C: {
                        emplace_ind16("rol", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x0D:
                    case 0x1D:
                    case 0x2D: {
                        emplace_ind16("asr", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x0E:
                    case 0x1E:
                    case 0x2E: {
                        emplace_ind16("ror", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x0F:
                    case 0x1F:
                    case 0x2F: {
                        emplace_ind16("lsr", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x30: {
                        emplace_ext("com");
                        break;
                    }
                    case 0x31: {
                        emplace_ext("dec");
                        break;
                    }
                    case 0x32: {
                        emplace_ext("neg");
                        break;
                    }
                    case 0x33: {
                        emplace_ext("inc");
                        break;
                    }
                    case 0x34: {
                        emplace_ext("asl");
                        break;
                    }
                    case 0x35: {
                        emplace_ext("clr");
                        break;
                    }
                    case 0x36: {
                        emplace_ext("tst");
                        break;
                    }
                    case 0x3C: {
                        emplace_ext("rol");
                        break;
                    }
                    case 0x3D: {
                        emplace_ext("asr");
                        break;
                    }
                    case 0x3E: {
                        emplace_ext("ror");
                        break;
                    }
                    case 0x3F: {
                        emplace_ext("lsr");
                        break;
                    }
                    case 0x40:
                    case 0x50:
                    case 0x60: {
                        emplace_ind16("suba", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x41:
                    case 0x51:
                    case 0x61: {
                        emplace_ind16("adda", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x42:
                    case 0x52:
                    case 0x62: {
                        emplace_ind16("sbca", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x43:
                    case 0x53:
                    case 0x63: {
                        emplace_ind16("adca", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x44:
                    case 0x54:
                    case 0x64: {
                        emplace_ind16("eora", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x45:
                    case 0x55:
                    case 0x65: {
                        emplace_ind16("ldaa", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x46:
                    case 0x56:
                    case 0x66: {
                        emplace_ind16("anda", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x47:
                    case 0x57:
                    case 0x67: {
                        emplace_ind16("oraa", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x48:
                    case 0x58:
                    case 0x68: {
                        emplace_ind16("cmpa", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x49:
                    case 0x59:
                    case 0x69: {
                        emplace_ind16("bita", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x4A:
                    case 0x5A:
                    case 0x6A: {
                        emplace_ind16("staa", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x4C:
                    case 0x5C:
                    case 0x6C: {
                        emplace_ind16("cpx", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x4D:
                    case 0x5D:
                    case 0x6D: {
                        emplace_ind16("cpy", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x4E:
                    case 0x5E:
                    case 0x6E: {
                        emplace_ind16("cpz", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x4F:
                    case 0x5F:
                    case 0x6F: {
                        emplace_ind16("cps", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x70: {
                        emplace_ext("suba");
                        break;
                    }
                    case 0x71: {
                        emplace_ext("adda");
                        break;
                    }
                    case 0x72: {
                        emplace_ext("sbca");
                        break;
                    }
                    case 0x73: {
                        emplace_ext("adca");
                        break;
                    }
                    case 0x74: {
                        emplace_ext("eora");
                        break;
                    }
                    case 0x75: {
                        emplace_ext("ldaa");
                        break;
                    }
                    case 0x76: {
                        emplace_ext("anda");
                        break;
                    }
                    case 0x77: {
                        emplace_ext("oraa");
                        break;
                    }
                    case 0x78: {
                        emplace_ext("cmpa");
                        break;
                    }
                    case 0x79: {
                        emplace_ext("bita");
                        break;
                    }
                    case 0x7A: {
                        emplace_ext("staa");
                        break;
                    }
                    case 0x7C: {
                        emplace_ext("cpx");
                        break;
                    }
                    case 0x7D: {
                        emplace_ext("cpy");
                        break;
                    }
                    case 0x7E: {
                        emplace_ext("cpz");
                        break;
                    }
                    case 0x7F: {
                        emplace_ext("cps");
                        break;
                    }
                    case 0x8C:
                    case 0x9C:
                    case 0xAC: {
                        emplace_ind16("stx", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x8D:
                    case 0x9D:
                    case 0xAD: {
                        emplace_ind16("sty", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x8E:
                    case 0x9E:
                    case 0xAE: {
                        emplace_ind16("stz", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x8F:
                    case 0x9F:
                    case 0xAF: {
                        emplace_ind16("sts", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0xBC: {
                        emplace_ext("stx");
                        break;
                    }
                    case 0xBD: {
                        emplace_ext("sty");
                        break;
                    }
                    case 0xBE: {
                        emplace_ext("stz");
                        break;
                    }
                    case 0xBF: {
                        emplace_ext("sts");
                        break;
                    }
                    case 0xC0:
                    case 0xD0:
                    case 0xE0: {
                        emplace_ind16("subb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC1:
                    case 0xD1:
                    case 0xE1: {
                        emplace_ind16("addb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC2:
                    case 0xD2:
                    case 0xE2: {
                        emplace_ind16("sbcb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC3:
                    case 0xD3:
                    case 0xE3: {
                        emplace_ind16("adcb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC4:
                    case 0xD4:
                    case 0xE4: {
                        emplace_ind16("eorb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC5:
                    case 0xD5:
                    case 0xE5: {
                        emplace_ind16("ldab", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC6:
                    case 0xD6:
                    case 0xE6: {
                        emplace_ind16("andb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC7:
                    case 0xD7:
                    case 0xE7: {
                        emplace_ind16("orab", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC8:
                    case 0xD8:
                    case 0xE8: {
                        emplace_ind16("cmpb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC9:
                    case 0xD9:
                    case 0xE9: {
                        emplace_ind16("bitb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xCA:
                    case 0xDA:
                    case 0xEA: {
                        emplace_ind16("stab", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xCC:
                    case 0xDC:
                    case 0xEC: {
                        emplace_ind16("ldx", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xCD:
                    case 0xDD:
                    case 0xED: {
                        emplace_ind16("ldy", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xCE:
                    case 0xDE:
                    case 0xEE: {
                        emplace_ind16("ldz", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xCF:
                    case 0xDF:
                    case 0xEF: {
                        emplace_ind16("lds", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xF0: {
                        emplace_ext("subb");
                        break;
                    }
                    case 0xF1: {
                        emplace_ext("addb");
                        break;
                    }
                    case 0xF2: {
                        emplace_ext("sbcb");
                        break;
                    }
                    case 0xF3: {
                        emplace_ext("adcb");
                        break;
                    }
                    case 0xF4: {
                        emplace_ext("eorb");
                        break;
                    }
                    case 0xF5: {
                        emplace_ext("ldab");
                        break;
                    }
                    case 0xF6: {
                        emplace_ext("andb");
                        break;
                    }
                    case 0xF7: {
                        emplace_ext("orab");
                        break;
                    }
                    case 0xF8: {
                        emplace_ext("cmpb");
                        break;
                    }
                    case 0xF9: {
                        emplace_ext("bitb");
                        break;
                    }
                    case 0xFA: {
                        emplace_ext("stab");
                        break;
                    }
                    case 0xFC: {
                        emplace_ext("ldx");
                        break;
                    }
                    case 0xFD: {
                        emplace_ext("ldy");
                        break;
                    }
                    case 0xFE: {
                        emplace_ext("ldz");
                        break;
                    }
                    case 0xFF: {
                        emplace_ext("lds");
                        break;
                    }
                    default: {
                        std::cerr << std::format("Illegal secondary opcode {:02X}{:02X} at {:06X}", op_code, op_code2, op_addr) << "!\n";
                        break;
                    }
                }
                break;
            }
            case 0x27: {
                switch(auto const op_code2 = read_u8()) {
                    case 0x00:
                    case 0x10:
                    case 0x20: {
                        emplace_ind16("comw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x01:
                    case 0x11:
                    case 0x21: {
                        emplace_ind16("decw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x02:
                    case 0x12:
                    case 0x22: {
                        emplace_ind16("negw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x03:
                    case 0x13:
                    case 0x23: {
                        emplace_ind16("incw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x04:
                    case 0x14:
                    case 0x24: {
                        emplace_ind16("aslw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x05:
                    case 0x15:
                    case 0x25: {
                        emplace_ind16("clrw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x06:
                    case 0x16:
                    case 0x26: {
                        emplace_ind16("tstw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x08:
                    case 0x18:
                    case 0x28: {
                        emplace_m16ind16("bclrw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x09:
                    case 0x19:
                    case 0x29: {
                        emplace_m16ind16("bsetw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x0C:
                    case 0x1C:
                    case 0x2C: {
                        emplace_ind16("rolw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x0D:
                    case 0x1D:
                    case 0x2D: {
                        emplace_ind16("asrw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x0E:
                    case 0x1E:
                    case 0x2E: {
                        emplace_ind16("rorw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x0F:
                    case 0x1F:
                    case 0x2F: {
                        emplace_ind16("lsrw", op_code2, 0x10, 0x20);
                        break;
                    }
                    case 0x30: {
                        emplace_ext("comw");
                        break;
                    }
                    case 0x31: {
                        emplace_ext("decw");
                        break;
                    }
                    case 0x32: {
                        emplace_ext("negw");
                        break;
                    }
                    case 0x33: {
                        emplace_ext("incw");
                        break;
                    }
                    case 0x34: {
                        emplace_ext("aslw");
                        break;
                    }
                    case 0x35: {
                        emplace_ext("clrw");
                        break;
                    }
                    case 0x36: {
                        emplace_ext("tstw");
                        break;
                    }
                    case 0x3C: {
                        emplace_ext("rolw");
                        break;
                    }
                    case 0x3D: {
                        emplace_ext("asrw");
                        break;
                    }
                    case 0x3E: {
                        emplace_ext("rorw");
                        break;
                    }
                    case 0x3F: {
                        emplace_ext("lsrw");
                        break;
                    }
                    case 0x40:
                    case 0x50:
                    case 0x60: {
                        emplace_eind("suba", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x41:
                    case 0x51:
                    case 0x61: {
                        emplace_eind("adda", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x42:
                    case 0x52:
                    case 0x62: {
                        emplace_eind("sbca", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x43:
                    case 0x53:
                    case 0x63: {
                        emplace_eind("adca", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x44:
                    case 0x54:
                    case 0x64: {
                        emplace_eind("eora", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x45:
                    case 0x55:
                    case 0x65: {
                        emplace_eind("ldaa", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x46:
                    case 0x56:
                    case 0x66: {
                        emplace_eind("anda", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x47:
                    case 0x57:
                    case 0x67: {
                        emplace_eind("oraa", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x48:
                    case 0x58:
                    case 0x68: {
                        emplace_eind("cmpa", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x49:
                    case 0x59:
                    case 0x69: {
                        emplace_eind("bita", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x4A:
                    case 0x5A:
                    case 0x6A: {
                        emplace_eind("staa", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x4C: {
                        emplace("nop");
                        break;
                    }
                    case 0x4D: {
                        emplace("tyx");
                        break;
                    }
                    case 0x4E: {
                        emplace("tzx");
                        break;
                    }
                    case 0x4F: {
                        emplace("tsx");
                        break;
                    }
                    case 0x5C: {
                        emplace("txy");
                        break;
                    }
                    case 0x5E: {
                        emplace("tzy");
                        break;
                    }
                    case 0x5F: {
                        emplace("tsy");
                        break;
                    }
                    case 0x6C: {
                        emplace("txz");
                        break;
                    }
                    case 0x6D: {
                        emplace("tyz");
                        break;
                    }
                    case 0x6F: {
                        emplace("tsz");
                        break;
                    }
                    case 0x70: {
                        emplace("come");
                        break;
                    }
                    case 0x71: {
                        emplace_ext("lded");
                        break;
                    }
                    case 0x72: {
                        emplace("nege");
                        break;
                    }
                    case 0x73: {
                        emplace_ext("sted");
                        break;
                    }
                    case 0x74: {
                        emplace("asle");
                        break;
                    }
                    case 0x75: {
                        emplace("clre");
                        break;
                    }
                    case 0x76: {
                        emplace("tste");
                        break;
                    }
                    case 0x77: {
                        emplace("rti");
                        break;
                    }
                    case 0x78: {
                        emplace("ade");
                        break;
                    }
                    case 0x79: {
                        emplace("sde");
                        break;
                    }
                    case 0x7A: {
                        emplace("xgde");
                        break;
                    }
                    case 0x7B: {
                        emplace("tde");
                        break;
                    }
                    case 0x7C: {
                        emplace("role");
                        break;
                    }
                    case 0x7D: {
                        emplace("asre");
                        break;
                    }
                    case 0x7E: {
                        emplace("rore");
                        break;
                    }
                    case 0x7F: {
                        emplace("lsre");
                        break;
                    }
                    case 0x80:
                    case 0x90:
                    case 0xA0: {
                        emplace_eind("subd", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x81:
                    case 0x91:
                    case 0xA1: {
                        emplace_eind("addd", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x82:
                    case 0x92:
                    case 0xA2: {
                        emplace_eind("sbcd", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x83:
                    case 0x93:
                    case 0xA3: {
                        emplace_eind("adcd", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x84:
                    case 0x94:
                    case 0xA4: {
                        emplace_eind("eord", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x85:
                    case 0x95:
                    case 0xA5: {
                        emplace_eind("ldd", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x86:
                    case 0x96:
                    case 0xA6: {
                        emplace_eind("andd", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x87:
                    case 0x97:
                    case 0xA7: {
                        emplace_eind("ord", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x88:
                    case 0x98:
                    case 0xA8: {
                        emplace_eind("cpd", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0x8A:
                    case 0x9A:
                    case 0xAA: {
                        emplace_eind("std", op_code2, 0x90, 0xA0);
                        break;
                    }
                    case 0xB0: {
                        emplace_ext("ldhi");
                        break;
                    }
                    case 0xB1: {
                        emplace("tedm");
                        break;
                    }
                    case 0xB2: {
                        emplace("tem");
                        break;
                    }
                    case 0xB3: {
                        emplace("tmxed");
                        break;
                    }
                    case 0xB4: {
                        emplace("tmer");
                        break;
                    }
                    case 0xB5: {
                        emplace("tmet");
                        break;
                    }
                    case 0xB6: {
                        emplace("aslm");
                        break;
                    }
                    case 0xB7: {
                        emplace("clrm");
                        break;
                    }
                    case 0xB8: {
                        emplace("pshmac");
                        break;
                    }
                    case 0xB9: {
                        emplace("pulmac");
                        break;
                    }
                    case 0xBA: {
                        emplace("asrm");
                        break;
                    }
                    case 0xBB: {
                        emplace("tekb");
                        break;
                    }
                    case 0xC0:
                    case 0xD0:
                    case 0xE0: {
                        emplace_eind("subb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC1:
                    case 0xD1:
                    case 0xE1: {
                        emplace_eind("addb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC2:
                    case 0xD2:
                    case 0xE2: {
                        emplace_eind("sbcb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC3:
                    case 0xD3:
                    case 0xE3: {
                        emplace_eind("adcb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC4:
                    case 0xD4:
                    case 0xE4: {
                        emplace_eind("eorb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC5:
                    case 0xD5:
                    case 0xE5: {
                        emplace_eind("ldab", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC6:
                    case 0xD6:
                    case 0xE6: {
                        emplace_eind("andb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC7:
                    case 0xD7:
                    case 0xE7: {
                        emplace_eind("orab", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC8:
                    case 0xD8:
                    case 0xE8: {
                        emplace_eind("cmpb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC9:
                    case 0xD9:
                    case 0xE9: {
                        emplace_eind("bitb", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xCA:
                    case 0xDA:
                    case 0xEA: {
                        emplace_eind("stab", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xF0: {
                        emplace("comd");
                        break;
                    }
                    case 0xF1: {
                        emplace("lpstop");
                        break;
                    }
                    case 0xF2: {
                        emplace("negd");
                        break;
                    }
                    case 0xF3: {
                        emplace("wai");
                        break;
                    }
                    case 0xF4: {
                        emplace("asld");
                        break;
                    }
                    case 0xF5: {
                        emplace("clrd");
                        break;
                    }
                    case 0xF6: {
                        emplace("tstd");
                        break;
                    }
                    case 0xF7: {
                        emplace("rts");
                        break;
                    }
                    case 0xF8: {
                        emplace("sxt");
                        break;
                    }
                    case 0xF9: {
                        emplace_rel16("lbsr");
                        break;
                    }
                    case 0xFA: {
                        emplace("tbek");
                        break;
                    }
                    case 0xFB: {
                        emplace("ted");
                        break;
                    }
                    case 0xFC: {
                        emplace("rold");
                        break;
                    }
                    case 0xFD: {
                        emplace("asrd");
                        break;
                    }
                    case 0xFE: {
                        emplace("rord");
                        break;
                    }
                    case 0xFF: {
                        emplace("lsrd");
                        break;
                    }
                    default: {
                        std::cerr << std::format("Illegal secondary opcode {:02X}{:02X} at {:06X}", op_code, op_code2, op_addr) << "!\n";
                        break;
                    }
                }
                break;
            }
            case 0x30: {
                emplace_ixpext("movb");
                break;
            }
            case 0x31: {
                emplace_ixpext("movw");
                break;
            }
            case 0x32: {
                emplace_extixp("movb");
                break;
            }
            case 0x33: {
                emplace_extixp("movw");
                break;
            }
            case 0x34: {
                emplace_imm8("pshm");
                break;
            }
            case 0x35: {
                emplace_imm8("pulm");
                break;
            }
            case 0x36: {
                emplace_rel8("bsr");
                break;
            }
            case 0x37: {
                switch(auto const op_code2 = read_u8()) {
                    case 0x00: {
                        emplace("coma");
                        break;
                    }
                    case 0x01: {
                        emplace("deca");
                        break;
                    }
                    case 0x02: {
                        emplace("nega");
                        break;
                    }
                    case 0x03: {
                        emplace("inca");
                        break;
                    }
                    case 0x04: {
                        emplace("asla");
                        break;
                    }
                    case 0x05: {
                        emplace("clra");
                        break;
                    }
                    case 0x06: {
                        emplace("tsta");
                        break;
                    }
                    case 0x07: {
                        emplace("tba");
                        break;
                    }
                    case 0x08: {
                        emplace("psha");
                        break;
                    }
                    case 0x09: {
                        emplace("pula");
                        break;
                    }
                    case 0x0A: {
                        emplace("sba");
                        break;
                    }
                    case 0x0B: {
                        emplace("aba");
                        break;
                    }
                    case 0x0C: {
                        emplace("rola");
                        break;
                    }
                    case 0x0D: {
                        emplace("asra");
                        break;
                    }
                    case 0x0E: {
                        emplace("rora");
                        break;
                    }
                    case 0x0F: {
                        emplace("lsra");
                        break;
                    }
                    case 0x10: {
                        emplace("comb");
                        break;
                    }
                    case 0x11: {
                        emplace("decb");
                        break;
                    }
                    case 0x12: {
                        emplace("negb");
                        break;
                    }
                    case 0x13: {
                        emplace("incb");
                        break;
                    }
                    case 0x14: {
                        emplace("aslb");
                        break;
                    }
                    case 0x15: {
                        emplace("clrb");
                        break;
                    }
                    case 0x16: {
                        emplace("tstb");
                        break;
                    }
                    case 0x17: {
                        emplace("tab");
                        break;
                    }
                    case 0x18: {
                        emplace("pshb");
                        break;
                    }
                    case 0x19: {
                        emplace("pulb");
                        break;
                    }
                    case 0x1A: {
                        emplace("xgab");
                        break;
                    }
                    case 0x1B: {
                        emplace("cba");
                        break;
                    }
                    case 0x1C: {
                        emplace("rolb");
                        break;
                    }
                    case 0x1D: {
                        emplace("asrb");
                        break;
                    }
                    case 0x1E: {
                        emplace("rorb");
                        break;
                    }
                    case 0x1F: {
                        emplace("lsrb");
                        break;
                    }
                    case 0x20: {
                        emplace("swi");
                        break;
                    }
                    case 0x21: {
                        emplace("daa");
                        break;
                    }
                    case 0x22: {
                        emplace("ace");
                        break;
                    }
                    case 0x23: {
                        emplace("aced");
                        break;
                    }
                    case 0x24: {
                        emplace("mul");
                        break;
                    }
                    case 0x25: {
                        emplace("emul");
                        break;
                    }
                    case 0x26: {
                        emplace("emuls");
                        break;
                    }
                    case 0x27: {
                        emplace("fmuls");
                        break;
                    }
                    case 0x28: {
                        emplace("ediv");
                        break;
                    }
                    case 0x29: {
                        emplace("edivs");
                        break;
                    }
                    case 0x2A: {
                        emplace("idiv");
                        break;
                    }
                    case 0x2B: {
                        emplace("fdiv");
                        break;
                    }
                    case 0x2C: {
                        emplace("tpd");
                        break;
                    }
                    case 0x2D: {
                        emplace("tdp");
                        break;
                    }
                    case 0x2F: {
                        emplace("tdmsk");
                        break;
                    }
                    case 0x30: {
                        emplace_imm16("sube");
                        break;
                    }
                    case 0x31: {
                        emplace_imm16("adde");
                        break;
                    }
                    case 0x32: {
                        emplace_imm16("sbce");
                        break;
                    }
                    case 0x33: {
                        emplace_imm16("adce");
                        break;
                    }
                    case 0x34: {
                        emplace_imm16("eore");
                        break;
                    }
                    case 0x35: {
                        emplace_imm16("lde");
                        break;
                    }
                    case 0x36: {
                        emplace_imm16("ande");
                        break;
                    }
                    case 0x37: {
                        emplace_imm16("ore");
                        break;
                    }
                    case 0x38: {
                        emplace_imm16("cpe");
                        break;
                    }
                    case 0x3A: {
                        emplace_imm16("andp");
                        break;
                    }
                    case 0x3B: {
                        emplace_imm16("orp");
                        break;
                    }
                    case 0x3C: {
                        emplace_imm16("aix");
                        break;
                    }
                    case 0x3D: {
                        emplace_imm16("aiy");
                        break;
                    }
                    case 0x3E: {
                        emplace_imm16("aiz");
                        break;
                    }
                    case 0x3F: {
                        emplace_imm16("ais");
                        break;
                    }
                    case 0x40:
                    case 0x50:
                    case 0x60: {
                        emplace_ind16("sube", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x41:
                    case 0x51:
                    case 0x61: {
                        emplace_ind16("adde", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x42:
                    case 0x52:
                    case 0x62: {
                        emplace_ind16("sbce", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x43:
                    case 0x53:
                    case 0x63: {
                        emplace_ind16("adce", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x44:
                    case 0x54:
                    case 0x64: {
                        emplace_ind16("eore", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x45:
                    case 0x55:
                    case 0x65: {
                        emplace_ind16("lde", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x46:
                    case 0x56:
                    case 0x66: {
                        emplace_ind16("ande", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x47:
                    case 0x57:
                    case 0x67: {
                        emplace_ind16("ore", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x48:
                    case 0x58:
                    case 0x68: {
                        emplace_ind16("cpe", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x4A:
                    case 0x5A:
                    case 0x6A: {
                        emplace_ind16("ste", op_code2, 0x50, 0x60);
                        break;
                    }
                    case 0x4C: {
                        emplace("xgex");
                        break;
                    }
                    case 0x4D: {
                        emplace("aex");
                        break;
                    }
                    case 0x4E: {
                        emplace("txs");
                        break;
                    }
                    case 0x4F: {
                        emplace("abx");
                        break;
                    }
                    case 0x5C: {
                        emplace("xgey");
                        break;
                    }
                    case 0x5D: {
                        emplace("aey");
                        break;
                    }
                    case 0x5E: {
                        emplace("tys");
                        break;
                    }
                    case 0x5F: {
                        emplace("aby");
                        break;
                    }
                    case 0x6C: {
                        emplace("xgez");
                        break;
                    }
                    case 0x6D: {
                        emplace("aez");
                        break;
                    }
                    case 0x6E: {
                        emplace("tzs");
                        break;
                    }
                    case 0x6F: {
                        emplace("abz");
                        break;
                    }
                    case 0x70: {
                        emplace_ext("sube");
                        break;
                    }
                    case 0x71: {
                        emplace_ext("adde");
                        break;
                    }
                    case 0x72: {
                        emplace_ext("sbce");
                        break;
                    }
                    case 0x73: {
                        emplace_ext("adce");
                        break;
                    }
                    case 0x74: {
                        emplace_ext("eore");
                        break;
                    }
                    case 0x75: {
                        emplace_ext("lde");
                        break;
                    }
                    case 0x76: {
                        emplace_ext("ande");
                        break;
                    }
                    case 0x77: {
                        emplace_ext("ore");
                        break;
                    }
                    case 0x78: {
                        emplace_ext("cpe");
                        break;
                    }
                    case 0x7A: {
                        emplace_ext("ste");
                        break;
                    }
                    case 0x7C: {
                        emplace_imm16("cpx");
                        break;
                    }
                    case 0x7D: {
                        emplace_imm16("cpy");
                        break;
                    }
                    case 0x7E: {
                        emplace_imm16("cpz");
                        break;
                    }
                    case 0x7F: {
                        emplace_imm16("cps");
                        break;
                    }
                    case 0x80: {
                        emplace_rel16("lbra");
                        break;
                    }
                    case 0x81: {
                        emplace_rel16("lbrn");
                        break;
                    }
                    case 0x82: {
                        emplace_rel16("lbhi");
                        break;
                    }
                    case 0x83: {
                        emplace_rel16("lbls");
                        break;
                    }
                    case 0x84: {
                        emplace_rel16("lbcc");
                        break;
                    }
                    case 0x85: {
                        emplace_rel16("lbcs");
                        break;
                    }
                    case 0x86: {
                        emplace_rel16("lbne");
                        break;
                    }
                    case 0x87: {
                        emplace_rel16("lbeq");
                        break;
                    }
                    case 0x88: {
                        emplace_rel16("lbvc");
                        break;
                    }
                    case 0x89: {
                        emplace_rel16("lbvs");
                        break;
                    }
                    case 0x8A: {
                        emplace_rel16("lbpl");
                        break;
                    }
                    case 0x8B: {
                        emplace_rel16("lbmi");
                        break;
                    }
                    case 0x8C: {
                        emplace_rel16("lbge");
                        break;
                    }
                    case 0x8D: {
                        emplace_rel16("lblt");
                        break;
                    }
                    case 0x8E: {
                        emplace_rel16("lbgt");
                        break;
                    }
                    case 0x8F: {
                        emplace_rel16("lble");
                        break;
                    }
                    case 0x90: {
                        emplace_rel16("lbmv");
                        break;
                    }
                    case 0x91: {
                        emplace_rel16("lbev");
                        break;
                    }
                    case 0x9C: {
                        emplace("tbxk");
                        break;
                    }
                    case 0x9D: {
                        emplace("tbyk");
                        break;
                    }
                    case 0x9E: {
                        emplace("tbzk");
                        break;
                    }
                    case 0x9F: {
                        emplace("tbsk");
                        break;
                    }
                    case 0xA6: {
                        emplace("bgnd");
                        break;
                    }
                    case 0xAC: {
                        emplace("txkb");
                        break;
                    }
                    case 0xAD: {
                        emplace("tykb");
                        break;
                    }
                    case 0xAE: {
                        emplace("tzkb");
                        break;
                    }
                    case 0xAF: {
                        emplace("tskb");
                        break;
                    }
                    case 0xB0: {
                        emplace_imm16("subd");
                        break;
                    }
                    case 0xB1: {
                        emplace_imm16("addd");
                        break;
                    }
                    case 0xB2: {
                        emplace_imm16("sbcd");
                        break;
                    }
                    case 0xB3: {
                        emplace_imm16("adcd");
                        break;
                    }
                    case 0xB4: {
                        emplace_imm16("eord");
                        break;
                    }
                    case 0xB5: {
                        emplace_imm16("ldd");
                        break;
                    }
                    case 0xB6: {
                        emplace_imm16("andd");
                        break;
                    }
                    case 0xB7: {
                        emplace_imm16("ord");
                        break;
                    }
                    case 0xB8: {
                        emplace_imm16("cpd");
                        break;
                    }
                    case 0xBC: {
                        emplace_imm16("ldx");
                        break;
                    }
                    case 0xBD: {
                        emplace_imm16("ldy");
                        break;
                    }
                    case 0xBE: {
                        emplace_imm16("ldz");
                        break;
                    }
                    case 0xBF: {
                        emplace_imm16("lds");
                        break;
                    }
                    case 0xC0:
                    case 0xD0:
                    case 0xE0: {
                        emplace_ind16("subd", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC1:
                    case 0xD1:
                    case 0xE1: {
                        emplace_ind16("addd", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC2:
                    case 0xD2:
                    case 0xE2: {
                        emplace_ind16("sbcd", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC3:
                    case 0xD3:
                    case 0xE3: {
                        emplace_ind16("adcd", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC4:
                    case 0xD4:
                    case 0xE4: {
                        emplace_ind16("eord", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC5:
                    case 0xD5:
                    case 0xE5: {
                        emplace_ind16("ldd", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC6:
                    case 0xD6:
                    case 0xE6: {
                        emplace_ind16("andd", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC7:
                    case 0xD7:
                    case 0xE7: {
                        emplace_ind16("ord", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xC8:
                    case 0xD8:
                    case 0xE8: {
                        emplace_ind16("cpd", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xCA:
                    case 0xDA:
                    case 0xEA: {
                        emplace_ind16("std", op_code2, 0xD0, 0xE0);
                        break;
                    }
                    case 0xCC: {
                        emplace("xgdx");
                        break;
                    }
                    case 0xCD: {
                        emplace("adx");
                        break;
                    }
                    case 0xDC: {
                        emplace("xgdy");
                        break;
                    }
                    case 0xDD: {
                        emplace("ady");
                        break;
                    }
                    case 0xEC: {
                        emplace("xgdz");
                        break;
                    }
                    case 0xED: {
                        emplace("adz");
                        break;
                    }
                    case 0xF0: {
                        emplace_ext("subd");
                        break;
                    }
                    case 0xF1: {
                        emplace_ext("addd");
                        break;
                    }
                    case 0xF2: {
                        emplace_ext("sbcd");
                        break;
                    }
                    case 0xF3: {
                        emplace_ext("adcd");
                        break;
                    }
                    case 0xF4: {
                        emplace_ext("eord");
                        break;
                    }
                    case 0xF5: {
                        emplace_ext("ldd");
                        break;
                    }
                    case 0xF6: {
                        emplace_ext("andd");
                        break;
                    }
                    case 0xF7: {
                        emplace_ext("ord");
                        break;
                    }
                    case 0xF8: {
                        emplace_ext("cpd");
                        break;
                    }
                    case 0xFA: {
                        emplace_ext("std");
                        break;
                    }
                    case 0xFC: {
                        emplace("tpa");
                        break;
                    }
                    case 0xFD: {
                        emplace("tap");
                        break;
                    }
                    case 0xFE: {
                        emplace_extext("movb");
                        break;
                    }
                    case 0xFF: {
                        emplace_extext("movw");
                        break;
                    }
                    default: {
                        std::cerr << std::format("Illegal secondary opcode {:02X}{:02X} at {:06X}", op_code, op_code2, op_addr) << "!\n";
                        break;
                    }
                }
                break;
            }
            case 0x38: {
                emplace_mext("bclr");
                break;
            }
            case 0x39: {
                emplace_mext("bset");
                break;
            }
            case 0x3A: {
                emplace_mextrel("brclr");
                break;
            }
            case 0x3B: {
                emplace_mextrel("brset");
                break;
            }
            case 0x3C: {
                emplace_imm8("aix");
                break;
            }
            case 0x3D: {
                emplace_imm8("aiy");
                break;
            }
            case 0x3E: {
                emplace_imm8("aiz");
                break;
            }
            case 0x3F: {
                emplace_imm8("ais");
                break;
            }
            case 0x40:
            case 0x50:
            case 0x60: {
                emplace_ind8("suba", op_code, 0x50, 0x60);
                break;
            }
            case 0x41:
            case 0x51:
            case 0x61: {
                emplace_ind8("adda", op_code, 0x50, 0x60);
                break;
            }
            case 0x42:
            case 0x52:
            case 0x62: {
                emplace_ind8("sbca", op_code, 0x50, 0x60);
                break;
            }
            case 0x43:
            case 0x53:
            case 0x63: {
                emplace_ind8("adca", op_code, 0x50, 0x60);
                break;
            }
            case 0x44:
            case 0x54:
            case 0x64: {
                emplace_ind8("eora", op_code, 0x50, 0x60);
                break;
            }
            case 0x45:
            case 0x55:
            case 0x65: {
                emplace_ind8("ldaa", op_code, 0x50, 0x60);
                break;
            }
            case 0x46:
            case 0x56:
            case 0x66: {
                emplace_ind8("anda", op_code, 0x50, 0x60);
                break;
            }
            case 0x47:
            case 0x57:
            case 0x67: {
                emplace_ind8("oraa", op_code, 0x50, 0x60);
                break;
            }
            case 0x48:
            case 0x58:
            case 0x68: {
                emplace_ind8("cmpa", op_code, 0x50, 0x60);
                break;
            }
            case 0x49:
            case 0x59:
            case 0x69: {
                emplace_ind8("bita", op_code, 0x50, 0x60);
                break;
            }
            case 0x4A:
            case 0x5A:
            case 0x6A: {
                emplace_ind8("staa", op_code, 0x50, 0x60);
                break;
            }
            case 0x4B:
            case 0x5B:
            case 0x6B: {
                emplace_ind20("jmp", op_code, 0x50, 0x60);
                break;
            }
            case 0x4C:
            case 0x5C:
            case 0x6C: {
                emplace_ind8("cpx", op_code, 0x50, 0x60);
                break;
            }
            case 0x4D:
            case 0x5D:
            case 0x6D: {
                emplace_ind8("cpy", op_code, 0x50, 0x60);
                break;
            }
            case 0x4E:
            case 0x5E:
            case 0x6E: {
                emplace_ind8("cpz", op_code, 0x50, 0x60);
                break;
            }
            case 0x4F:
            case 0x5F:
            case 0x6F: {
                emplace_ind8("cps", op_code, 0x50, 0x60);
                break;
            }
            case 0x70: {
                emplace_imm8("suba");
                break;
            }
            case 0x71: {
                emplace_imm8("adda");
                break;
            }
            case 0x72: {
                emplace_imm8("sbca");
                break;
            }
            case 0x73: {
                emplace_imm8("adca");
                break;
            }
            case 0x74: {
                emplace_imm8("eora");
                break;
            }
            case 0x75: {
                emplace_imm8("ldaa");
                break;
            }
            case 0x76: {
                emplace_imm8("anda");
                break;
            }
            case 0x77: {
                emplace_imm8("oraa");
                break;
            }
            case 0x78: {
                emplace_imm8("cmpa");
                break;
            }
            case 0x79: {
                emplace_imm8("bita");
                break;
            }
            case 0x7A: {
                emplace_ext20("jmp");
                break;
            }
            case 0x7B: {
                emplace_mac8("mac");
                break;
            }
            case 0x7C: {
                emplace_imm8("adde");
                break;
            }
            case 0x80:
            case 0x90:
            case 0xA0: {
                emplace_ind8("subd", op_code, 0x90, 0xA0);
                break;
            }
            case 0x81:
            case 0x91:
            case 0xA1: {
                emplace_ind8("addd", op_code, 0x90, 0xA0);
                break;
            }
            case 0x82:
            case 0x92:
            case 0xA2: {
                emplace_ind8("sbcd", op_code, 0x90, 0xA0);
                break;
            }
            case 0x83:
            case 0x93:
            case 0xA3: {
                emplace_ind8("adcd", op_code, 0x90, 0xA0);
                break;
            }
            case 0x84:
            case 0x94:
            case 0xA4: {
                emplace_ind8("eord", op_code, 0x90, 0xA0);
                break;
            }
            case 0x85:
            case 0x95:
            case 0xA5: {
                emplace_ind8("ldd", op_code, 0x90, 0xA0);
                break;
            }
            case 0x86:
            case 0x96:
            case 0xA6: {
                emplace_ind8("andd", op_code, 0x90, 0xA0);
                break;
            }
            case 0x87:
            case 0x97:
            case 0xA7: {
                emplace_ind8("orad", op_code, 0x90, 0xA0);
                break;
            }
            case 0x88:
            case 0x98:
            case 0xA8: {
                emplace_ind8("cpd", op_code, 0x90, 0xA0);
                break;
            }
            case 0x89:
            case 0x99:
            case 0xA9: {
                emplace_ind20("jsr", op_code, 0x90, 0xA0);
                break;
            }
            case 0x8A:
            case 0x9A:
            case 0xAA: {
                emplace_ind8("std", op_code, 0x90, 0xA0);
                break;
            }
            case 0x8B:
            case 0x9B:
            case 0xAB: {
                emplace_m8ind8rel8("brset", op_code, 0x90, 0xA0);
                break;
            }
            case 0x8C:
            case 0x9C:
            case 0xAC: {
                emplace_ind8("stx", op_code, 0x90, 0xA0);
                break;
            }
            case 0x8D:
            case 0x9D:
            case 0xAD: {
                emplace_ind8("sty", op_code, 0x90, 0xA0);
                break;
            }
            case 0x8E:
            case 0x9E:
            case 0xAE: {
                emplace_ind8("stz", op_code, 0x90, 0xA0);
                break;
            }
            case 0x8F:
            case 0x9F:
            case 0xAF: {
                emplace_ind8("sts", op_code, 0x90, 0xA0);
                break;
            }
            case 0xB0: {
                emplace_rel8("bra");
                break;
            }
            case 0xB1: {
                emplace_rel8("brn");
                break;
            }
            case 0xB2: {
                emplace_rel8("bhi");
                break;
            }
            case 0xB3: {
                emplace_rel8("bls");
                break;
            }
            case 0xB4: {
                emplace_rel8("bcc");
                break;
            }
            case 0xB5: {
                emplace_rel8("bcs");
                break;
            }
            case 0xB6: {
                emplace_rel8("bne");
                break;
            }
            case 0xB7: {
                emplace_rel8("beq");
                break;
            }
            case 0xB8: {
                emplace_rel8("bvc");
                break;
            }
            case 0xB9: {
                emplace_rel8("bvs");
                break;
            }
            case 0xBA: {
                emplace_rel8("bpl");
                break;
            }
            case 0xBB: {
                emplace_rel8("bmi");
                break;
            }
            case 0xBC: {
                emplace_rel8("bge");
                break;
            }
            case 0xBD: {
                emplace_rel8("blt");
                break;
            }
            case 0xBE: {
                emplace_rel8("bgt");
                break;
            }
            case 0xBF: {
                emplace_rel8("ble");
                break;
            }
            case 0xC0:
            case 0xD0:
            case 0xE0: {
                emplace_ind8("subb", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xC1:
            case 0xD1:
            case 0xE1: {
                emplace_ind8("addb", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xC2:
            case 0xD2:
            case 0xE2: {
                emplace_ind8("sbcb", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xC3:
            case 0xD3:
            case 0xE3: {
                emplace_ind8("adcb", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xC4:
            case 0xD4:
            case 0xE4: {
                emplace_ind8("eorb", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xC5:
            case 0xD5:
            case 0xE5: {
                emplace_ind8("ldab", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xC6:
            case 0xD6:
            case 0xE6: {
                emplace_ind8("andb", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xC7:
            case 0xD7:
            case 0xE7: {
                emplace_ind8("orab", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xC8:
            case 0xD8:
            case 0xE8: {
                emplace_ind8("cmpb", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xC9:
            case 0xD9:
            case 0xE9: {
                emplace_ind8("bitb", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xCA:
            case 0xDA:
            case 0xEA: {
                emplace_ind8("stab", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xCB:
            case 0xDB:
            case 0xEB: {
                emplace_m8ind8rel8("brclr", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xCC:
            case 0xDC:
            case 0xEC: {
                emplace_ind8("ldx", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xCD:
            case 0xDD:
            case 0xED: {
                emplace_ind8("ldy", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xCE:
            case 0xDE:
            case 0xEE: {
                emplace_ind8("ldz", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xCF:
            case 0xDF:
            case 0xEF: {
                emplace_ind8("lds", op_code, 0xD0, 0xE0);
                break;
            }
            case 0xF0: {
                emplace_imm8("subb");
                break;
            }
            case 0xF1: {
                emplace_imm8("addb");
                break;
            }
            case 0xF2: {
                emplace_imm8("sbcb");
                break;
            }
            case 0xF3: {
                emplace_imm8("adcb");
                break;
            }
            case 0xF4: {
                emplace_imm8("eorb");
                break;
            }
            case 0xF5: {
                emplace_imm8("ldab");
                break;
            }
            case 0xF6: {
                emplace_imm8("andb");
                break;
            }
            case 0xF7: {
                emplace_imm8("orab");
                break;
            }
            case 0xF8: {
                emplace_imm8("cmpb");
                break;
            }
            case 0xF9: {
                emplace_imm8("bitb");
                break;
            }
            case 0xFA: {
                emplace_ext20("jsr");
                break;
            }
            case 0xFB: {
                emplace_mac8("rmac");
                break;
            }
            case 0xFC: {
                emplace_imm8("addd");
                break;
            }
            default: {
                std::cerr << std::format("Illegal opcode {:02X} at {:06X}", op_code, op_addr) << "!\n";
                break;
            }
        }
    }
    return tokens;
}

int main(int argc, char** argv) {
    if(argc != 3) {
        print_usage();
        return 0;
    }

    auto const hc16_binary = read_hc16_file(argv[1]);
    if(!hc16_binary.data) {
        std::cerr << "Unable to read file: " << argv[1] << std::endl;
        return -1;
    }

    auto const base_address = std::stoi(argv[2], nullptr, 16);
    auto tokens = tokenize(hc16_binary, base_address);

    for(auto token : tokens) { std::cout << std::format("{:04X}: {}", token.address, token.disassembly) << '\n'; }
    std::cout << std::endl;

    return 0;
}