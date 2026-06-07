#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#endif
#ifdef __APPLE__
#include <net/if_dl.h>
#endif
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
extern "C" {
#include "../deps/miniz_tdef.c"
#include "../deps/miniz_tinfl.c"
#include "../deps/miniz.c"
}
#include "../deps/micro-bunzip.c"
namespace grc {
static std::vector<uint8_t> bzip2Decompress(const uint8_t* data, size_t size) {
    bunzip_data *bd = nullptr;
    std::vector<uint8_t> result;
    int ret = start_bunzip(&bd, -1, (char*)data, size);
    if (ret != RETVAL_OK) {
        if (bd) {
            if (bd->dbuf) free(bd->dbuf);
            free(bd);
        }
        return result;
    }
    while (true) {
        char outbuf[IOBUF_SIZE];
        memset(outbuf, 0, IOBUF_SIZE);
        int got = write_bunzip_data(bd, -1, outbuf, IOBUF_SIZE);
        if (got < 0) {
            if (got == RETVAL_LAST_BLOCK && bd->headerCRC == bd->totalCRC) break;
            break;
        }
        if (got > 0) result.insert(result.end(), outbuf, outbuf + got);
    }
    if (bd->dbuf) free(bd->dbuf);
    free(bd);
    return result;
}
static uint8_t writeGByte(int value) { return (value & 0xFF) + 0x20; }
static int decodeGByte(uint8_t byte) { return (byte & 0xFF) - 0x20; }
static void writeGShort(std::vector<uint8_t>& buf, int value) {
    buf.push_back(((value >> 7) & 0xFF) + 32);
    buf.push_back((value & 0x7F) + 32);
}
static int decodeGShort(const uint8_t* data) {
    return ((data[0] - 32) << 7) + (data[1] - 32);
}
static void writeGInt3(std::vector<uint8_t>& buf, int value) {
    buf.push_back(((value >> 14) & 0x7F) + 32);
    buf.push_back(((value >> 7) & 0x7F) + 32);
    buf.push_back((value & 0x7F) + 32);
}
static int decodeGInt3(const uint8_t* data) {
    return ((data[0] - 32) << 14) + ((data[1] - 32) << 7) + (data[2] - 32);
}
static void writeGInt5(std::vector<uint8_t>& buf, int value) {
    buf.push_back(((value >> 28) & 0x7F) + 32);
    buf.push_back(((value >> 21) & 0x7F) + 32);
    buf.push_back(((value >> 14) & 0x7F) + 32);
    buf.push_back(((value >> 7) & 0x7F) + 32);
    buf.push_back((value & 0x7F) + 32);
}
std::string get1PlusTextNetString(const std::string& s) {
    if (s.length() > 223) return std::string(1, (char)255) + s.substr(223);
    return std::string(1, (char)(32 + s.length())) + s;
}
static std::string replaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return str;
}

static uint32_t md5LeftRotate(uint32_t value, uint32_t amount) {
    return (value << amount) | (value >> (32 - amount));
}

static std::array<uint8_t, 16> md5Digest(const uint8_t* data, size_t length) {
    static const uint32_t shifts[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    static const uint32_t table[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    uint64_t bit_length = (uint64_t)length * 8;
    size_t padded_length = length + 1;
    while ((padded_length % 64) != 56) padded_length++;
    std::vector<uint8_t> msg(padded_length + 8, 0);
    if (data && length > 0) memcpy(msg.data(), data, length);
    msg[length] = 0x80;
    for (int i = 0; i < 8; ++i) msg[padded_length + i] = (uint8_t)((bit_length >> (8 * i)) & 0xff);

    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;
    for (size_t offset = 0; offset < msg.size(); offset += 64) {
        uint32_t words[16];
        for (int i = 0; i < 16; ++i) {
            size_t j = offset + i * 4;
            words[i] = (uint32_t)msg[j] | ((uint32_t)msg[j + 1] << 8) | ((uint32_t)msg[j + 2] << 16) | ((uint32_t)msg[j + 3] << 24);
        }
        uint32_t a = a0, b = b0, c = c0, d = d0;
        for (uint32_t i = 0; i < 64; ++i) {
            uint32_t f = 0, g = 0;
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
            uint32_t tmp = d;
            d = c;
            c = b;
            b = b + md5LeftRotate(a + f + table[i] + words[g], shifts[i]);
            a = tmp;
        }
        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }
    std::array<uint8_t, 16> digest{};
    uint32_t parts[] = { a0, b0, c0, d0 };
    for (int i = 0; i < 4; ++i) {
        digest[i * 4] = (uint8_t)(parts[i] & 0xff);
        digest[i * 4 + 1] = (uint8_t)((parts[i] >> 8) & 0xff);
        digest[i * 4 + 2] = (uint8_t)((parts[i] >> 16) & 0xff);
        digest[i * 4 + 3] = (uint8_t)((parts[i] >> 24) & 0xff);
    }
    return digest;
}

static std::string md5RevHex(const uint8_t* data, size_t length) {
    if (!data && length > 0) return "";
    std::array<uint8_t, 16> digest = md5Digest(data, length);
    std::string output;
    static const char* hex = "0123456789abcdef";
    output.reserve(32);
    for (uint8_t b : digest) {
        output += hex[b & 0x0f];
        output += hex[(b >> 4) & 0x0f];
    }
    return output;
}

static std::string md5Hex(const uint8_t* data, size_t length) {
    if (!data && length > 0) return "";
    std::array<uint8_t, 16> digest = md5Digest(data, length);
    std::string output;
    static const char* hex = "0123456789abcdef";
    output.reserve(32);
    for (uint8_t b : digest) {
        output += hex[(b >> 4) & 0x0f];
        output += hex[b & 0x0f];
    }
    return output;
}

static std::string md5RevHex(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    return md5RevHex(data.empty() ? nullptr : data.data(), data.size());
}

static std::string md5Hex(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    return md5Hex(data.empty() ? nullptr : data.data(), data.size());
}

static std::vector<uint8_t> readWindowsDigitalProductId() {
    std::vector<uint8_t> result;
#ifdef _WIN32
    const char* paths[] = {
        "Software\\Microsoft\\Windows\\CurrentVersion",
        "Software\\Microsoft\\Windows NT\\CurrentVersion"
    };
    for (const char* path : paths) {
        HKEY key = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS &&
            RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key) != ERROR_SUCCESS) {
            continue;
        }
        DWORD type = 0;
        DWORD size = 0;
        LONG query = RegQueryValueExA(key, "DigitalProductId", nullptr, &type, nullptr, &size);
        if (query == ERROR_SUCCESS && size > 0 && (type == REG_BINARY || type == REG_NONE)) {
            result.resize(size);
            query = RegQueryValueExA(key, "DigitalProductId", nullptr, &type, result.data(), &size);
            if (query == ERROR_SUCCESS && size > 0) {
                result.resize(size);
                RegCloseKey(key);
                return result;
            }
        }
        RegCloseKey(key);
        result.clear();
    }
#endif
#ifndef _WIN32
    const char* paths[] = { "/etc/machine-id", "/var/lib/dbus/machine-id" };
    for (const char* path : paths) {
        std::ifstream file(path, std::ios::binary);
        if (!file) continue;
        std::string value((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        value.erase(std::remove(value.begin(), value.end(), '\n'), value.end());
        value.erase(std::remove(value.begin(), value.end(), '\r'), value.end());
        if (!value.empty()) {
            result.assign(value.begin(), value.end());
            return result;
        }
    }
    char host[256] = {0};
    if (gethostname(host, sizeof(host) - 1) == 0 && host[0]) result.assign(host, host + strlen(host));
#endif
    return result;
}

static std::vector<uint8_t> readLinuxEth0MacAddress() {
    std::vector<uint8_t> result;
#ifdef __linux__
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return result;

    struct ifreq request;
    memset(&request, 0, sizeof(request));
    strncpy(request.ifr_name, "eth0", IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &request) == 0) {
        const uint8_t* mac = (const uint8_t*)request.ifr_hwaddr.sa_data;
        result.assign(mac, mac + 6);
    }
    closesocket(fd);
#endif
    return result;
}

static std::vector<uint8_t> readFirstValidMacAddress() {
    std::vector<uint8_t> result;
#ifdef _WIN32
    ULONG size = 0;
    if (GetAdaptersInfo(nullptr, &size) != ERROR_BUFFER_OVERFLOW || size == 0) return result;
    std::vector<uint8_t> buffer(size);
    IP_ADAPTER_INFO* adapters = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
    if (GetAdaptersInfo(adapters, &size) != NO_ERROR) return result;
    for (IP_ADAPTER_INFO* adapter = adapters; adapter; adapter = adapter->Next) {
        if (adapter->AddressLength < 6) continue;
        bool valid_ip = false;
        for (IP_ADDR_STRING* ip = &adapter->IpAddressList; ip; ip = ip->Next) {
            std::string address = ip->IpAddress.String ? ip->IpAddress.String : "";
            if (!address.empty() && address != "0.0.0.0" && address != "127.0.0.1" && address != "0") {
                valid_ip = true;
                break;
            }
        }
        if (valid_ip) {
            result.assign(adapter->Address, adapter->Address + 6);
            return result;
        }
    }
#endif
#ifndef _WIN32
    struct ifaddrs* addrs = nullptr;
    if (getifaddrs(&addrs) != 0) return result;
    for (struct ifaddrs* item = addrs; item; item = item->ifa_next) {
        if (!item->ifa_addr) continue;
#ifdef __linux__
        if (item->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll* s = (struct sockaddr_ll*)item->ifa_addr;
            if (s->sll_halen >= 6) {
                const uint8_t* mac = (const uint8_t*)s->sll_addr;
                bool nonzero = false;
                for (int i = 0; i < 6; ++i) nonzero = nonzero || mac[i] != 0;
                if (nonzero) {
                    result.assign(mac, mac + 6);
                    break;
                }
            }
        }
#endif
#ifdef __APPLE__
        if (item->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl* s = (struct sockaddr_dl*)item->ifa_addr;
            if (s->sdl_alen >= 6) {
                const uint8_t* mac = (const uint8_t*)LLADDR(s);
                bool nonzero = false;
                for (int i = 0; i < 6; ++i) nonzero = nonzero || mac[i] != 0;
                if (nonzero) {
                    result.assign(mac, mac + 6);
                    break;
                }
            }
        }
#endif
    }
    freeifaddrs(addrs);
#endif
    return result;
}

static std::vector<uint8_t> readLinuxEtcInodeBytes() {
    std::vector<uint8_t> result;
#ifdef __linux__
    struct stat info;
    if (stat("/etc", &info) == 0) {
        uint64_t value = (uint64_t)info.st_ino;
        for (int i = 0; i < 4; ++i) result.push_back((uint8_t)((value >> (8 * i)) & 0xff));
    }
#endif
    return result;
}

static std::vector<uint8_t> readVolumeSerialBytes() {
    std::vector<uint8_t> result;
#ifdef _WIN32
    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        result.push_back((uint8_t)(serial & 0xff));
        result.push_back((uint8_t)((serial >> 8) & 0xff));
        result.push_back((uint8_t)((serial >> 16) & 0xff));
        result.push_back((uint8_t)((serial >> 24) & 0xff));
    }
#endif
#ifndef _WIN32
    struct stat info;
    if (stat("/", &info) == 0) {
        uint64_t value = (uint64_t)info.st_dev;
        for (int i = 0; i < 8; ++i) result.push_back((uint8_t)((value >> (8 * i)) & 0xff));
    }
#endif
    return result;
}

static std::string generatePcidList() {
#ifdef _WIN32
    std::string windows_id = md5RevHex(readWindowsDigitalProductId());
    std::string network_id = md5RevHex(readFirstValidMacAddress());
    std::string harddisk_id = md5RevHex(readVolumeSerialBytes());
    return "win," + windows_id + "," + network_id + "," + harddisk_id;
#elif defined(__linux__)
    std::string network_id = md5Hex(readLinuxEth0MacAddress());
    std::string system_id = md5Hex(readLinuxEtcInodeBytes());
    return "linux," + network_id + "," + system_id + ",";
#else
    std::string machine_id = md5RevHex(readWindowsDigitalProductId());
    std::string network_id = md5RevHex(readFirstValidMacAddress());
    std::string disk_id = md5RevHex(readVolumeSerialBytes());
    return "mac," + machine_id + "," + network_id + "," + disk_id;
#endif
}
static std::string gtokenize(const std::string& text) {
    std::string cleaned = text;
    size_t pos = 0;
    while ((pos = cleaned.find('\r', pos)) != std::string::npos) {
        cleaned.erase(pos, 1);
    }
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < cleaned.length()) {
        size_t end = cleaned.find('\n', start);
        if (end == std::string::npos) {
            lines.push_back(cleaned.substr(start));
            break;
        }
        lines.push_back(cleaned.substr(start, end - start));
        start = end + 1;
    }
    if (cleaned.empty() || cleaned.back() == '\n') lines.push_back("");
    std::vector<std::string> result;
    for (const auto& line : lines) {
        if (line.empty()) {
            result.push_back("");
            continue;
        }
        bool needs_quotes = false;
        if (!line.empty() && line[0] == '"') {
            needs_quotes = true;
        }
        for (char c : line) {
            if (c < 33 || c > 126 || c == ',' || c == '/') {
                needs_quotes = true;
                break;
            }
        }
        bool all_space = true;
        for (char c : line) {
            if (c != ' ') {
                all_space = false;
                break;
            }
        }
        if (all_space && !line.empty()) needs_quotes = true;
        if (needs_quotes) {
            std::string escaped;
            for (char c : line) {
                if (c == '\\') escaped += "\\\\";
                else if (c == '"') escaped += "\"\"";
                else escaped += c;
            }
            result.push_back("\"" + escaped + "\"");
        } else {
            result.push_back(line);
        }
    }
    std::string output;
    for (size_t i = 0; i < result.size(); ++i) {
        if (i > 0) output += ",";
        output += result[i];
    }
    return output;
}
static std::string gtokenizeReverse(const std::string& content) {
    std::vector<std::string> output;
    bool currently_inside_quotes = false;
    bool line_quoted = false;
    size_t pos = 0;
    size_t i = 0;
    while (i < content.length()) {
        if (content[i] == '"') {
            if (currently_inside_quotes) {
                if (i + 1 < content.length() && content[i + 1] == '"') {
                    i += 2;
                    continue;
                }
            }
            line_quoted = true;
            currently_inside_quotes = !currently_inside_quotes;
        }
        if (!currently_inside_quotes) {
            if (content[i] == ',' || i + 1 == content.length()) {
                size_t line_start = pos + (line_quoted ? 1 : 0);
                size_t line_length = i - pos - (line_quoted ? 2 : 0) + (i + 1 == content.length() && content[i] != ',' ? 1 : 0);
                std::string line = content.substr(line_start, line_length);
                if (line_quoted) {
                    size_t dq_pos = 0;
                    while ((dq_pos = line.find("\"\"", dq_pos)) != std::string::npos) {
                        line.replace(dq_pos, 2, "\"");
                        dq_pos += 1;
                    }
                    size_t bs_pos = 0;
                    while ((bs_pos = line.find("\\\\", bs_pos)) != std::string::npos) {
                        line.replace(bs_pos, 2, "\\");
                        bs_pos += 1;
                    }
                    line.erase(std::remove(line.begin(), line.end(), '\n'), line.end());
                    line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
                }
                output.push_back(line);
                pos = i + 1;
                line_quoted = false;
            }
        }
        i++;
    }
    std::string result;
    for (size_t j = 0; j < output.size(); ++j) {
        if (j > 0) result += "\n";
        result += output[j];
    }
    return result;
}
static int readGByteAt(const std::vector<uint8_t>& data, size_t offset) {
    if (offset >= data.size()) return 0;
    return decodeGByte(data[offset]);
}
static int readGShortAt(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 1 >= data.size()) return 0;
    return decodeGShort(data.data() + offset);
}
static int readGInt5At(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 4 >= data.size()) return 0;
    int value = ((data[offset] - 32) << 28);
    value += ((data[offset+1] - 32) << 21);
    value += ((data[offset+2] - 32) << 14);
    value += ((data[offset+3] - 32) << 7);
    value += (data[offset+4] - 32);
    return value;
}
static int readGInt5(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset + 4 >= data.size()) return 0;
    int value = ((data[offset] - 32) << 28);
    value += ((data[offset+1] - 32) << 21);
    value += ((data[offset+2] - 32) << 14);
    value += ((data[offset+3] - 32) << 7);
    value += (data[offset+4] - 32);
    offset += 5;
    return value;
}
static std::string readLengthString(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset >= data.size()) return "";
    int length = decodeGByte(data[offset]);
    offset++;
    if (offset + length > data.size()) return "";
    std::string result(data.begin() + offset, data.begin() + offset + length);
    offset += length;
    return result;
}
static std::string readCommaText(const std::vector<uint8_t>& data, size_t offset, int length = -1) {
    std::string text;
    if (length == -1) {
        text = std::string(data.begin() + offset, data.end());
    } else {
        if (offset + length > data.size()) return "";
        text = std::string(data.begin() + offset, data.begin() + offset + length);
    }
    return gtokenizeReverse(text);
}
std::string gtokenizeString(const std::string& text) { return gtokenize(text); }
std::string gtokenizeReverseString(const std::string& content) { return gtokenizeReverse(content); }
static std::vector<uint8_t> scrambleData(const uint8_t* data, size_t len, uint32_t seed, uint8_t compression_type) {
    std::vector<uint8_t> result(data, data + len);
    uint32_t mask = 0x4A80B38;
    const uint32_t MASK_ROTATION = 0x8088405;
    int rotations = (compression_type == 0x02) ? 12 : 4;
    size_t offset = 0;
    while (offset < 4 * rotations && offset < len) {
        mask = (mask * MASK_ROTATION + seed) & 0xFFFFFFFF;
        for (size_t index = offset; index < len && index < offset + 4; ++index) {
            uint8_t byte_mask = (mask >> (8 * (index % 4))) & 0xFF;
            result[index] = data[index] ^ byte_mask;
        }
        offset += 4;
    }
    return result;
}
static std::vector<uint8_t> zlibCompress(const uint8_t* data, size_t len) {
    mz_ulong compressed_size = mz_compressBound(len);
    std::vector<uint8_t> compressed(compressed_size);
    if (mz_compress(compressed.data(), &compressed_size, data, len) != MZ_OK) return std::vector<uint8_t>(data, data + len);
    compressed.resize(compressed_size);
    return compressed;
}
static std::vector<uint8_t> zlibDecompress(const uint8_t* data, size_t len) {
    std::vector<uint8_t> decompressed(len * 10);
    mz_ulong decompressed_size = decompressed.size();
    while (mz_uncompress(decompressed.data(), &decompressed_size, data, len) == MZ_BUF_ERROR) {
        decompressed.resize(decompressed.size() * 2);
        decompressed_size = decompressed.size();
    }
    decompressed.resize(decompressed_size);
    return decompressed;
}
class GRCProtocol {
public:
    uint32_t encryption_key;
    GRCProtocol() : encryption_key(0), iterator_out(0x4A80B38), iterator_in(0x4A80B38) {}
    void setEncryptionKey(uint32_t key) { encryption_key = key; }
    std::vector<uint8_t> encrypt(const uint8_t* data, size_t len, uint8_t compression_type) {
        if (encryption_key == 0 || len == 0) return std::vector<uint8_t>(data, data + len);
        std::vector<uint8_t> result(data, data + len);
        int limit = (compression_type == 0x02) ? 0x0C : 0x04;
        for (size_t i = 0; i < len; ++i) {
            if (i % 4 == 0) {
                if (limit <= 0) break;
                limit--;
                iterator_out = (iterator_out * 0x8088405 + encryption_key) & 0xFFFFFFFF;
            }
            result[i] ^= (iterator_out >> ((i % 4) * 8)) & 0xFF;
        }
        return result;
    }
    std::vector<uint8_t> decrypt(const uint8_t* data, size_t len, uint8_t compression_type) {
        if (encryption_key == 0 || len == 0) return std::vector<uint8_t>(data, data + len);
        std::vector<uint8_t> result(data, data + len);
        int limit = (compression_type == 0x02) ? 0x0C : 0x04;
        for (size_t i = 0; i < len; ++i) {
            if (i % 4 == 0) {
                if (limit <= 0) break;
                limit--;
                iterator_in = (iterator_in * 0x8088405 + encryption_key) & 0xFFFFFFFF;
            }
            result[i] ^= (iterator_in >> ((i % 4) * 8)) & 0xFF;
        }
        return result;
    }
    std::vector<uint8_t> sendPacket(uint8_t packet_type, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> payload;
        payload.push_back(packet_type + 32);
        payload.insert(payload.end(), data.begin(), data.end());
        payload.push_back(0x0A);
        uint8_t compression_type = (data.size() > 40) ? 0x04 : 0x02;
        std::vector<uint8_t> compressed_payload = (compression_type == 0x04) ? zlibCompress(payload.data(), payload.size()) : payload;
        std::vector<uint8_t> final_packet;
        if (encryption_key != 0) {
            std::vector<uint8_t> encrypted_buffer = encrypt(compressed_payload.data(), compressed_payload.size(), compression_type);
            uint16_t length = encrypted_buffer.size() + 1;
            final_packet.push_back((length >> 8) & 0xFF);
            final_packet.push_back(length & 0xFF);
            final_packet.push_back(compression_type);
            final_packet.insert(final_packet.end(), encrypted_buffer.begin(), encrypted_buffer.end());
        } else {
            uint16_t length = compressed_payload.size();
            final_packet.push_back((length >> 8) & 0xFF);
            final_packet.push_back(length & 0xFF);
            final_packet.insert(final_packet.end(), compressed_payload.begin(), compressed_payload.end());
        }
        return final_packet;
    }
    std::vector<uint8_t> rawBlock(const std::vector<uint8_t>& data) {
        uint8_t compression_type = (data.size() > 40) ? 0x04 : 0x02;
        std::vector<uint8_t> compressed_payload = (compression_type == 0x04) ? zlibCompress(data.data(), data.size()) : data;
        std::vector<uint8_t> final_packet;
        if (encryption_key != 0) {
            std::vector<uint8_t> encrypted_buffer = encrypt(compressed_payload.data(), compressed_payload.size(), compression_type);
            uint16_t length = encrypted_buffer.size() + 1;
            final_packet.push_back((length >> 8) & 0xFF);
            final_packet.push_back(length & 0xFF);
            final_packet.push_back(compression_type);
            final_packet.insert(final_packet.end(), encrypted_buffer.begin(), encrypted_buffer.end());
        } else {
            uint16_t length = compressed_payload.size();
            final_packet.push_back((length >> 8) & 0xFF);
            final_packet.push_back(length & 0xFF);
            final_packet.insert(final_packet.end(), compressed_payload.begin(), compressed_payload.end());
        }
        return final_packet;
    }
    std::vector<uint8_t> decryptPacket(const uint8_t* data, size_t len) {
        if (len < 1) return std::vector<uint8_t>();
        if (encryption_key != 0) {
            uint8_t compression_type = data[0];
            std::vector<uint8_t> decrypted = decrypt(data + 1, len - 1, compression_type);
            if (compression_type == 0x04) return zlibDecompress(decrypted.data(), decrypted.size());
            return decrypted;
        } else {
            return std::vector<uint8_t>(data, data + len);
        }
    }
private:
    uint32_t iterator_out;
    uint32_t iterator_in;
};
class NCProtocol {
public:
    std::vector<uint8_t> sendPacket(uint8_t packet_type, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> payload;
        payload.push_back(packet_type + 32);
        payload.insert(payload.end(), data.begin(), data.end());
        payload.push_back(0x0A);
        std::vector<uint8_t> compressed = zlibCompress(payload.data(), payload.size());
        std::vector<uint8_t> final_packet;
        uint16_t length = compressed.size();
        final_packet.push_back((length >> 8) & 0xFF);
        final_packet.push_back(length & 0xFF);
        final_packet.insert(final_packet.end(), compressed.begin(), compressed.end());
        return final_packet;
    }
    std::vector<uint8_t> decryptPacket(const uint8_t* data, size_t len) {
        return zlibDecompress(data, len);
    }
};
static bool sendAll(SOCKET sock, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int result = send(sock, (const char*)(data + sent), len - sent, 0);
        if (result <= 0) return false;
        sent += result;
    }
    return true;
}
static bool recvAll(SOCKET sock, uint8_t* data, size_t len) {
    size_t received = 0;
    while (received < len) {
        int result = recv(sock, (char*)(data + received), len - received, 0);
        if (result <= 0) return false;
        received += result;
    }
    return true;
}
struct ServerInfo {
    std::string name;
    std::string ip;
    int port;
    int players;
    std::string language;
    std::string description;
};
static std::vector<ServerInfo> fetchServerList(const std::string& host, int port, const std::string& account, const std::string& password, std::string& error) {
    std::vector<ServerInfo> servers;
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        error = "WSAStartup failed";
        return servers;
    }
#endif
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        error = "Failed to create socket";
        return servers;
    }
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) {
        error = "Failed to resolve host";
        closesocket(sock);
        return servers;
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *((struct in_addr*)he->h_addr);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        error = "Failed to connect to listserver";
        closesocket(sock);
        return servers;
    }
    std::vector<uint8_t> edition_payload;
    edition_payload.push_back(writeGByte(7));
    edition_payload.push_back(writeGByte(4));
    edition_payload.insert(edition_payload.end(), {'G','3','D','3','0','1','2','3','r','c','2'});
    edition_payload.push_back(0x0A);
    std::vector<uint8_t> compressed_edition = zlibCompress(edition_payload.data(), edition_payload.size());
    std::vector<uint8_t> edition_packet;
    uint16_t edition_len = compressed_edition.size();
    edition_packet.push_back((edition_len >> 8) & 0xFF);
    edition_packet.push_back(edition_len & 0xFF);
    edition_packet.insert(edition_packet.end(), compressed_edition.begin(), compressed_edition.end());
    if (!sendAll(sock, edition_packet.data(), edition_packet.size())) {
        error = "Failed to send edition packet";
        closesocket(sock);
        return servers;
    }
    std::vector<uint8_t> login_payload;
    login_payload.push_back(writeGByte(1));
    login_payload.push_back(writeGByte(account.length()));
    login_payload.insert(login_payload.end(), account.begin(), account.end());
    login_payload.push_back(writeGByte(password.length()));
    login_payload.insert(login_payload.end(), password.begin(), password.end());
    login_payload.push_back(0x0A);
    uint8_t compression_type = (login_payload.size() > 40) ? 0x04 : 0x02;
    std::vector<uint8_t> compressed_login = (compression_type == 0x04) ? zlibCompress(login_payload.data(), login_payload.size()) : login_payload;
    std::vector<uint8_t> encrypted_login = scrambleData(compressed_login.data(), compressed_login.size(), 4, compression_type);
    std::vector<uint8_t> login_packet;
    uint16_t login_len = encrypted_login.size() + 1;
    login_packet.push_back((login_len >> 8) & 0xFF);
    login_packet.push_back(login_len & 0xFF);
    login_packet.push_back(compression_type);
    login_packet.insert(login_packet.end(), encrypted_login.begin(), encrypted_login.end());
    if (!sendAll(sock, login_packet.data(), login_packet.size())) {
        error = "Failed to send login packet";
        closesocket(sock);
        return servers;
    }
    uint8_t length_bytes[2];
    if (!recvAll(sock, length_bytes, 2)) {
        error = "Failed to read packet length";
        closesocket(sock);
        return servers;
    }
    uint16_t packet_length = (length_bytes[0] << 8) | length_bytes[1];
    std::vector<uint8_t> packet_data(packet_length);
    if (!recvAll(sock, packet_data.data(), packet_length)) {
        error = "Failed to read packet data";
        closesocket(sock);
        return servers;
    }
    closesocket(sock);
    uint8_t format_type = packet_data[0];
    std::vector<uint8_t> unscrambled = scrambleData(packet_data.data() + 1, packet_data.size() - 1, 4, format_type);
    std::vector<uint8_t> decompressed = (format_type == 0x04) ? zlibDecompress(unscrambled.data(), unscrambled.size()) : unscrambled;
    if (decompressed.empty()) {
        error = "Failed to decompress server list";
        return servers;
    }
    size_t offset = 0;
    uint8_t packet_type = decodeGByte(decompressed[offset++]);
    if (packet_type != 0) {
        error = "Server rejected connection";
        return servers;
    }
    uint8_t server_count = decodeGByte(decompressed[offset++]);
    for (int i = 0; i < server_count && offset < decompressed.size(); ++i) {
        uint8_t attr_count = decodeGByte(decompressed[offset++]);
        std::vector<std::string> attributes;
        for (int j = 0; j < attr_count && offset < decompressed.size(); ++j) {
            uint8_t attr_len = decodeGByte(decompressed[offset++]);
            if (offset + attr_len > decompressed.size()) break;
            std::string attr_value(decompressed.begin() + offset, decompressed.begin() + offset + attr_len);
            attributes.push_back(attr_value);
            offset += attr_len;
        }
        if (attributes.size() >= 8) {
            ServerInfo info;
            info.name = attributes[0];
            info.language = attributes[1];
            info.description = attributes[2];
            info.players = std::atoi(attributes[5].c_str());
            info.ip = attributes[6];
            info.port = std::atoi(attributes[7].c_str());
            servers.push_back(info);
        }
    }
    return servers;
}
}
