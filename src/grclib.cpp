#include <grclib.h>
#include "protocol.cpp"
#include "IEnums.h"
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <functional>
#include <map>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#endif

struct RCConnection;
static int sendListerText(RCConnection* conn, const std::string& command, const std::string& value, int packet_id);

static char* grcStrdup(const char* text) {
    if (!text) text = "";
    size_t length = strlen(text) + 1;
    char* out = (char*)malloc(length);
    if (out) memcpy(out, text, length);
    return out;
}

static bool validateHeap(const char* context) {
#ifdef _WIN32
    HANDLE heaps[16];
    DWORD count = GetProcessHeaps(16, heaps);
    for (DWORD i = 0; i < count; i++) {
        if (!HeapValidate(heaps[i], 0, NULL)) {
            char buf[256];
            snprintf(buf, sizeof(buf), "HEAP CORRUPTION detected at %s (heap %u)\n", context, (unsigned)i);
            fwrite(buf, 1, strlen(buf), stderr);
            fflush(stderr);
            return false;
        }
    }
#else
    (void)context;
#endif
    return true;
}

struct FileBrowserFolderCacheEntry {
    std::string rights;
    std::string pattern;
};

struct FileBrowserFileCacheEntry {
    std::string path;
    std::string rights;
    int size;
    int modified;
    int is_directory;
};

static std::vector<std::string> splitText(const std::string& text, char delimiter) {
    std::vector<std::string> parts;
    std::string current;
    std::stringstream stream(text);
    while (std::getline(stream, current, delimiter)) {
        parts.push_back(current);
    }
    return parts;
}

static std::string trimText(const std::string& value) {
    size_t start = value.find_first_not_of(" \t\r\n\"");
    if (start == std::string::npos) return "";
    size_t end = value.find_last_not_of(" \t\r\n\"");
    return value.substr(start, end - start + 1);
}

static bool startsWithText(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

static std::string lowerText(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return value;
}

static std::string protocolTextNamespace() {
    static const unsigned char bytes[] = { 0x47, 0x72, 0x61, 0x61, 0x6c, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65 };
    return std::string((const char*)bytes, sizeof(bytes));
}

static std::string joinText(const std::vector<std::string>& values, size_t start, const std::string& separator) {
    std::string out;
    for (size_t i = start; i < values.size(); ++i) {
        if (i > start) out += separator;
        out += values[i];
    }
    return out;
}

static bool truthyText(const std::string& value) {
    std::string lower = lowerText(trimText(value));
    return lower == "true" || lower == "1" || lower == "yes";
}

static int decodeFileBrowserGInt5(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 4 >= data.size()) return 0;
    return ((data[offset] - 32) << 28) +
        ((data[offset + 1] - 32) << 21) +
        ((data[offset + 2] - 32) << 14) +
        ((data[offset + 3] - 32) << 7) +
        (data[offset + 4] - 32);
}

static int decodeAttrByte(uint8_t value) {
    return (int)value - 32;
}

static std::string readAttrString(const std::vector<uint8_t>& data, size_t& offset) {
    if (offset >= data.size()) return "";
    int length = decodeAttrByte(data[offset++]);
    if (length <= 0 || offset + (size_t)length > data.size()) return "";
    std::string value(data.begin() + offset, data.begin() + offset + length);
    offset += length;
    return value;
}

static bool isPlayerAttrStringProp(int prop_id) {
    return prop_id == 0 || prop_id == 10 || prop_id == 12 || prop_id == 20 ||
        prop_id == 21 || prop_id == 34 || prop_id == 35 || prop_id == 52 ||
        prop_id == 53 || prop_id == 75 || prop_id == 82 ||
        (prop_id >= 37 && prop_id <= 41) ||
        (prop_id >= 46 && prop_id <= 49) ||
        (prop_id >= 54 && prop_id <= 74);
}

static int playerAttrIndex(int prop_id) {
    if (prop_id >= 37 && prop_id <= 41) return prop_id - 36;
    if (prop_id >= 46 && prop_id <= 49) return prop_id - 40;
    if (prop_id >= 54 && prop_id <= 74) return prop_id - 44;
    return 0;
}

static std::string playerPropName(int prop_id) {
    int attr = playerAttrIndex(prop_id);
    if (attr) return "attr" + std::to_string(attr);
    switch (prop_id) {
        case 0: return "nick";
        case 1: return "max_power";
        case 2: return "current_power";
        case 3: return "rupees";
        case 4: return "arrows";
        case 5: return "bombs";
        case 6: return "glove_power";
        case 7: return "bomb_power";
        case 8: return "sword";
        case 9: return "shield";
        case 10: return "gani";
        case 11: return "head_image";
        case 12: return "chat";
        case 13: return "colors";
        case 14: return "id";
        case 15: return "x";
        case 16: return "y";
        case 17: return "direction";
        case 18: return "status";
        case 19: return "carry_sprite";
        case 20: return "level";
        case 21: return "horse_image";
        case 22: return "horse_bushes";
        case 23: return "effect_colors";
        case 24: return "carry_npc";
        case 25: return "ap_counter";
        case 26: return "magic_points";
        case 27: return "kills";
        case 28: return "deaths";
        case 29: return "online_seconds";
        case 30: return "ip_address";
        case 31: return "udp_port";
        case 32: return "alignment";
        case 33: return "additional_flags";
        case 34: return "account";
        case 35: return "body_image";
        case 36: return "rating";
        case 42: return "attached_npc";
        case 43: return "gmap_level_x";
        case 44: return "gmap_level_y";
        case 45: return "z";
        case 50: return "join_leave_level";
        case 51: return "connected";
        case 52: return "language";
        case 53: return "status_message";
        case 75: return "os_type";
        case 76: return "text_codepage";
        case 77: return "unknown77";
        case 78: return "precise_x";
        case 79: return "precise_y";
        case 80: return "precise_z";
        case 81: return "unknown81";
        case 82: return "community";
        default: return std::to_string(prop_id);
    }
}

static int decodeAttrGShort(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 1 >= data.size()) return 0;
    return (decodeAttrByte(data[offset]) << 7) + decodeAttrByte(data[offset + 1]);
}

static int decodeAttrGInt3(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 2 >= data.size()) return 0;
    return (decodeAttrByte(data[offset]) << 14) + (decodeAttrByte(data[offset + 1]) << 7) + decodeAttrByte(data[offset + 2]);
}

static double decodeAttrSigned14(const std::vector<uint8_t>& data, size_t offset) {
    int raw = decodeAttrGShort(data, offset);
    int value = raw >> 1;
    return ((raw & 1) ? -value : value) / 16.0;
}

struct PlayerPropValue {
    int id;
    std::string name;
    std::string value;
};

static bool readPlayerPropValue(const std::vector<uint8_t>& packet, size_t& offset, int prop_id, PlayerPropValue& out) {
    out.id = prop_id;
    out.name = playerPropName(prop_id);
    out.value.clear();

    if (isPlayerAttrStringProp(prop_id)) {
        out.value = readAttrString(packet, offset);
        return true;
    }
    if (prop_id == 1 || prop_id == 4 || prop_id == 5 || prop_id == 6 ||
        prop_id == 7 || prop_id == 17 || prop_id == 18 || prop_id == 19 ||
        prop_id == 22 || prop_id == 26 || prop_id == 32 || prop_id == 33 ||
        prop_id == 43 || prop_id == 44 || prop_id == 50 || prop_id == 51 ||
        prop_id == 77 || prop_id == 81) {
        if (offset >= packet.size()) return false;
        out.value = std::to_string(decodeAttrByte(packet[offset++]));
        return true;
    }
    if (prop_id == 2 || prop_id == 15 || prop_id == 16) {
        if (offset >= packet.size()) return false;
        out.value = std::to_string(decodeAttrByte(packet[offset++]) / 2.0);
        return true;
    }
    if (prop_id == 3 || prop_id == 24 || prop_id == 27 || prop_id == 28 ||
        prop_id == 29 || prop_id == 31 || prop_id == 76) {
        if (offset + 2 >= packet.size()) return false;
        out.value = std::to_string(decodeAttrGInt3(packet, offset));
        offset += 3;
        return true;
    }
    if (prop_id == 8 || prop_id == 9) {
        if (offset >= packet.size()) return false;
        int raw = decodeAttrByte(packet[offset++]);
        std::string image;
        if (raw >= 10 && offset < packet.size()) image = readAttrString(packet, offset);
        out.value = image.empty() ? std::to_string(raw) : (std::to_string(raw) + ":" + image);
        return true;
    }
    if (prop_id == 11) {
        if (offset >= packet.size()) return false;
        int head_len = decodeAttrByte(packet[offset++]);
        if (head_len > 0 && head_len < 100) {
            out.value = "head" + std::to_string(head_len) + ".gif";
            return true;
        }
        if (head_len >= 100 && offset + (size_t)(head_len - 100) <= packet.size()) {
            out.value.assign(packet.begin() + offset, packet.begin() + offset + (head_len - 100));
            offset += head_len - 100;
            return true;
        }
        out.value = "head0.gif";
        return true;
    }
    if (prop_id == 13) {
        if (offset + 4 >= packet.size()) return false;
        std::ostringstream colors;
        for (int i = 0; i < 5; ++i) {
            if (i) colors << ",";
            colors << decodeAttrByte(packet[offset + i]);
        }
        offset += 5;
        out.value = colors.str();
        return true;
    }
    if (prop_id == 14) {
        if (offset + 1 >= packet.size()) return false;
        out.value = std::to_string(decodeAttrGShort(packet, offset));
        offset += 2;
        return true;
    }
    if (prop_id == 23) {
        if (offset >= packet.size()) return false;
        int enabled = decodeAttrByte(packet[offset]);
        size_t count = enabled > 0 ? 4 : 1;
        if (offset + count > packet.size()) return false;
        std::ostringstream effect;
        for (size_t i = 0; i < count; ++i) {
            if (i) effect << ",";
            effect << decodeAttrByte(packet[offset + i]);
        }
        offset += count;
        out.value = effect.str();
        return true;
    }
    if (prop_id == 25) {
        if (offset + 1 >= packet.size()) return false;
        out.value = std::to_string(decodeAttrGShort(packet, offset));
        offset += 2;
        return true;
    }
    if (prop_id == 30) {
        if (offset + 4 >= packet.size()) return false;
        int b0 = decodeAttrByte(packet[offset]) & 0xff;
        int b1 = decodeAttrByte(packet[offset + 1]) & 0xff;
        int b2 = decodeAttrByte(packet[offset + 2]) & 0xff;
        int b3 = decodeAttrByte(packet[offset + 3]) & 0xff;
        int b4 = decodeAttrByte(packet[offset + 4]) & 0xff;
        int ip_value = (b0 << 28) | (b1 << 21) | (b2 << 14) | (b3 << 7) | b4;
        out.value = std::to_string((ip_value >> 24) & 0xff) + "." +
            std::to_string((ip_value >> 16) & 0xff) + "." +
            std::to_string((ip_value >> 8) & 0xff) + "." +
            std::to_string(ip_value & 0xff);
        offset += 5;
        return true;
    }
    if (prop_id == 36) {
        if (offset + 2 >= packet.size()) return false;
        int high = decodeAttrByte(packet[offset]);
        int low = decodeAttrByte(packet[offset + 1]);
        int frac = decodeAttrByte(packet[offset + 2]);
        out.value = std::to_string((high << 5) + (low >> 2)) + ":" + std::to_string(((low & 0x03) << 7) + frac);
        offset += 3;
        return true;
    }
    if (prop_id == 42) {
        if (offset + 3 >= packet.size()) return false;
        int kind = decodeAttrByte(packet[offset++]);
        int id = decodeAttrGInt3(packet, offset);
        offset += 3;
        out.value = std::to_string(kind) + ":" + std::to_string(id);
        return true;
    }
    if (prop_id == 45) {
        if (offset >= packet.size()) return false;
        out.value = std::to_string(decodeAttrByte(packet[offset++]) - 50);
        return true;
    }
    if (prop_id == 78 || prop_id == 79 || prop_id == 80) {
        if (offset + 1 >= packet.size()) return false;
        out.value = std::to_string(decodeAttrSigned14(packet, offset));
        offset += 2;
        return true;
    }
    return false;
}

static std::string jsonEscape(const std::string& value) {
    std::string out;
    for (unsigned char c : value) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    const char* hex = "0123456789abcdef";
                    out += "\\u00";
                    out += hex[(c >> 4) & 0x0f];
                    out += hex[c & 0x0f];
                } else {
                    out += (char)c;
                }
                break;
        }
    }
    return out;
}

static std::string bytesPreview(const std::vector<uint8_t>& data, size_t offset, size_t limit) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    size_t wanted_end = offset + limit;
    size_t end = data.size() < wanted_end ? data.size() : wanted_end;
    for (size_t i = offset; i < end; ++i) {
        if (!out.empty()) out += " ";
        uint8_t b = data[i];
        out += hex[(b >> 4) & 0x0F];
        out += hex[b & 0x0F];
    }
    if (end < data.size()) out += " ...";
    return out;
}

static std::string textPreview(const std::vector<uint8_t>& data, size_t offset, size_t limit) {
    std::string out;
    size_t wanted_end = offset + limit;
    size_t end = data.size() < wanted_end ? data.size() : wanted_end;
    for (size_t i = offset; i < end; ++i) {
        uint8_t b = data[i];
        out += (b >= 32 && b <= 126) ? (char)b : '.';
    }
    if (end < data.size()) out += "...";
    return out;
}

static void jsonAddPrefix(std::ostringstream& json, bool& first, const std::string& key) {
    if (!first) json << ",";
    first = false;
    json << "\"" << jsonEscape(key) << "\":";
}

static void jsonAddString(std::ostringstream& json, bool& first, const std::string& key, const std::string& value) {
    jsonAddPrefix(json, first, key);
    json << "\"" << jsonEscape(value) << "\"";
}

static void jsonAddNumber(std::ostringstream& json, bool& first, const std::string& key, double value) {
    jsonAddPrefix(json, first, key);
    json << value;
}

static void jsonAddStringArray(std::ostringstream& json, bool& first, const std::string& key, const std::vector<std::string>& values) {
    jsonAddPrefix(json, first, key);
    json << "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << jsonEscape(values[i]) << "\"";
    }
    json << "]";
}

static void jsonAddIntArray(std::ostringstream& json, bool& first, const std::string& key, const std::vector<int>& values) {
    jsonAddPrefix(json, first, key);
    json << "[";
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) json << ",";
        json << values[i];
    }
    json << "]";
}

static std::string jsonUnescape(const std::string& value) {
    std::string out;
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] != '\\' || i + 1 >= value.size()) {
            out += value[i];
            continue;
        }
        char c = value[++i];
        switch (c) {
            case '\\': out += '\\'; break;
            case '"': out += '"'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            default: out += c; break;
        }
    }
    return out;
}

static size_t findJsonValue(const std::string& json, const std::string& key) {
    std::string needle = "\"" + jsonEscape(key) + "\":";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return std::string::npos;
    pos += needle.size();
    while (pos < json.size() && std::isspace((unsigned char)json[pos])) ++pos;
    return pos;
}

static std::string jsonGetString(const std::string& json, const std::string& key, const std::string& fallback = "") {
    size_t pos = findJsonValue(json, key);
    if (pos == std::string::npos || pos >= json.size() || json[pos] != '"') return fallback;
    ++pos;
    std::string value;
    bool escaped = false;
    for (; pos < json.size(); ++pos) {
        char c = json[pos];
        if (!escaped && c == '"') break;
        if (!escaped && c == '\\') {
            escaped = true;
            value += c;
            continue;
        }
        escaped = false;
        value += c;
    }
    return jsonUnescape(value);
}

static double jsonGetNumber(const std::string& json, const std::string& key, double fallback = 0.0) {
    size_t pos = findJsonValue(json, key);
    if (pos == std::string::npos || pos >= json.size()) return fallback;
    size_t end = pos;
    while (end < json.size() && (std::isdigit((unsigned char)json[end]) || json[end] == '-' || json[end] == '+' || json[end] == '.')) {
        ++end;
    }
    if (end == pos) return fallback;
    try {
        return std::stod(json.substr(pos, end - pos));
    } catch (...) {
        return fallback;
    }
}

static std::vector<std::string> jsonGetStringArray(const std::string& json, const std::string& key) {
    std::vector<std::string> values;
    size_t pos = findJsonValue(json, key);
    if (pos == std::string::npos || pos >= json.size() || json[pos] != '[') return values;
    ++pos;
    while (pos < json.size() && json[pos] != ']') {
        while (pos < json.size() && (json[pos] == ',' || std::isspace((unsigned char)json[pos]))) ++pos;
        if (pos >= json.size() || json[pos] != '"') break;
        ++pos;
        std::string value;
        bool escaped = false;
        for (; pos < json.size(); ++pos) {
            char c = json[pos];
            if (!escaped && c == '"') {
                ++pos;
                break;
            }
            if (!escaped && c == '\\') {
                escaped = true;
                value += c;
                continue;
            }
            escaped = false;
            value += c;
        }
        values.push_back(jsonUnescape(value));
    }
    return values;
}

static std::vector<int> jsonGetIntArray(const std::string& json, const std::string& key) {
    std::vector<int> values;
    size_t pos = findJsonValue(json, key);
    if (pos == std::string::npos || pos >= json.size() || json[pos] != '[') return values;
    ++pos;
    while (pos < json.size() && json[pos] != ']') {
        while (pos < json.size() && (json[pos] == ',' || std::isspace((unsigned char)json[pos]))) ++pos;
        size_t end = pos;
        while (end < json.size() && (std::isdigit((unsigned char)json[end]) || json[end] == '-' || json[end] == '+')) ++end;
        if (end == pos) break;
        values.push_back(std::atoi(json.substr(pos, end - pos).c_str()));
        pos = end;
    }
    return values;
}

static bool jsonHasKey(const std::string& json, const std::string& key) {
    return findJsonValue(json, key) != std::string::npos;
}

static void writeAttrString(std::vector<uint8_t>& data, const std::string& value) {
    data.push_back(grc::writeGByte((int)value.size()));
    data.insert(data.end(), value.begin(), value.end());
}

static void writeRcLenString(std::vector<uint8_t>& data, const std::string& value) {
    if (value.size() < 0xe0) {
        data.push_back((uint8_t)(value.size() + 0x20));
        data.insert(data.end(), value.begin(), value.end());
    } else {
        data.push_back(0xff);
        data.insert(data.end(), value.begin(), value.begin() + 0xdf);
    }
}

static void writeAttrGInt3(std::vector<uint8_t>& data, int value) {
    data.push_back((uint8_t)(((value >> 14) & 0x7f) + 32));
    data.push_back((uint8_t)(((value >> 7) & 0x7f) + 32));
    data.push_back((uint8_t)((value & 0x7f) + 32));
}

static std::map<std::string, std::string> parseKeyValueLines(const std::string& text) {
    std::map<std::string, std::string> values;
    std::stringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        values[trimText(line.substr(0, eq))] = trimText(line.substr(eq + 1));
    }
    return values;
}

static const char* colorName(int color) {
    static const char* names[] = {
        "White", "Yellow", "Orange", "Pink", "Red", "Darkred",
        "Lightgreen", "Green", "Darkgreen", "Lightblue", "Blue", "Darkblue",
        "Brown", "Cynober", "Purple", "Darkpurple", "Lightgray", "Gray",
        "Black", "Transparent"
    };
    if (color >= 0 && color < 20) return names[color];
    return "";
}

static char* dupText(const std::string& text) {
    return grcStrdup(text.c_str());
}

static const std::vector<std::string>& rightsNames() {
    static const std::vector<std::string> names = {
        "Warp to XY", "Warp to Player", "Warp player", "Update Level",
        "Disconnect", "View Attributes", "Set Attributes", "Set Own Attributes",
        "Reset Attributes", "Admin Message", "Change Rights", "Ban Players",
        "Comments", "", "Staff Accounts", "Server Flags",
        "Server Options", "Folder Configuration", "Folder Rights", "NPC Control"
    };
    return names;
}

static const std::vector<std::string>& colorNames() {
    static const std::vector<std::string> names = {
        "White", "Yellow", "Orange", "Pink", "Red", "Darkred",
        "Lightgreen", "Green", "Darkgreen", "Lightblue", "Blue", "Darkblue",
        "Brown", "Cynober", "Purple", "Darkpurple", "Lightgray", "Gray",
        "Black", "Transparent"
    };
    return names;
}

static int colorIndexFromText(const std::string& value) {
    std::string trimmed = trimText(value);
    if (!trimmed.empty() && std::all_of(trimmed.begin(), trimmed.end(), [](unsigned char c) { return std::isdigit(c); })) {
        return std::atoi(trimmed.c_str());
    }
    std::string lower = lowerText(trimmed);
    const auto& names = colorNames();
    for (size_t i = 0; i < names.size(); ++i) {
        if (lowerText(names[i]) == lower) return (int)i;
    }
    return 0;
}

static std::string joinLines(const std::vector<std::string>& values) {
    std::ostringstream out;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) out << "\n";
        out << values[i];
    }
    return out.str();
}

static std::string packetMapToText(const std::vector<std::pair<int, std::string>>& values) {
    std::ostringstream out;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) out << "\n";
        out << values[i].first << "=" << values[i].second;
    }
    return out.str();
}

#define PACKET_NAME_PAIR(name) { name, #name }
#define PACKET_NAME_CASE(name) case name: return #name

static const char* incomingRcPacketName(int packet_id) {
    switch (packet_id) {
        PACKET_NAME_CASE(PLO_OTHERPLPROPS);
        PACKET_NAME_CASE(PLO_PLAYERPROPS);
        PACKET_NAME_CASE(PLO_BOMBADD);
        PACKET_NAME_CASE(PLO_TOALL);
        PACKET_NAME_CASE(PLO_DISCMESSAGE);
        PACKET_NAME_CASE(PLO_SIGNATURE);
        PACKET_NAME_CASE(PLO_FILESENDFAILED);
        PACKET_NAME_CASE(PLO_RC_ADMINMESSAGE);
        PACKET_NAME_CASE(PLO_PRIVATEMESSAGE);
        PACKET_NAME_CASE(PLO_NEWWORLDTIME);
        PACKET_NAME_CASE(PLO_STAFFGUILDS);
        PACKET_NAME_CASE(PLO_RC_ACCOUNTADD);
        PACKET_NAME_CASE(PLO_RC_ACCOUNTSTATUS);
        PACKET_NAME_CASE(PLO_RC_ACCOUNTNAME);
        PACKET_NAME_CASE(PLO_RC_ACCOUNTDEL);
        PACKET_NAME_CASE(PLO_RC_ACCOUNTPROPS);
        PACKET_NAME_CASE(PLO_ADDPLAYER);
        PACKET_NAME_CASE(PLO_DELPLAYER);
        PACKET_NAME_CASE(PLO_RC_ACCOUNTPROPSGET);
        PACKET_NAME_CASE(PLO_RC_ACCOUNTCHANGE);
        PACKET_NAME_CASE(PLO_RC_PLAYERPROPSCHANGE);
        PACKET_NAME_CASE(PLO_UNKNOWN60);
        PACKET_NAME_CASE(PLO_RC_SERVERFLAGSGET);
        PACKET_NAME_CASE(PLO_RC_PLAYERRIGHTSGET);
        PACKET_NAME_CASE(PLO_RC_PLAYERCOMMENTSGET);
        PACKET_NAME_CASE(PLO_RC_PLAYERBANGET);
        PACKET_NAME_CASE(PLO_RC_FILEBROWSER_DIRLIST);
        PACKET_NAME_CASE(PLO_RC_FILEBROWSER_DIR);
        PACKET_NAME_CASE(PLO_RC_FILEBROWSER_MESSAGE);
        PACKET_NAME_CASE(PLO_LARGEFILESTART);
        PACKET_NAME_CASE(PLO_LARGEFILEEND);
        PACKET_NAME_CASE(PLO_RC_ACCOUNTLISTGET);
        PACKET_NAME_CASE(PLO_RC_PLAYERPROPS);
        PACKET_NAME_CASE(PLO_RC_PLAYERPROPSGET);
        PACKET_NAME_CASE(PLO_RC_ACCOUNTGET);
        PACKET_NAME_CASE(PLO_RC_CHAT);
        PACKET_NAME_CASE(PLO_PROFILE);
        PACKET_NAME_CASE(PLO_RC_SERVEROPTIONSGET);
        PACKET_NAME_CASE(PLO_RC_FOLDERCONFIGGET);
        PACKET_NAME_CASE(PLO_NC_CONTROL);
        PACKET_NAME_CASE(PLO_NPCSERVERADDR);
        PACKET_NAME_CASE(PLO_NC_LEVELLIST);
        PACKET_NAME_CASE(PLO_SERVERTEXT);
        PACKET_NAME_CASE(PLO_LARGEFILESIZE);
        PACKET_NAME_CASE(PLO_RAWDATA);
        PACKET_NAME_CASE(PLO_BOARDPACKET);
        PACKET_NAME_CASE(PLO_FILE);
        PACKET_NAME_CASE(PLO_RC_MAXUPLOADFILESIZE);
        PACKET_NAME_CASE(PLO_STATUSLIST);
        PACKET_NAME_CASE(PLO_UNKNOWN190);
        PACKET_NAME_CASE(PLO_CLEARWEAPONS);
        default: return "UNKNOWN";
    }
}

struct RCConnection {
    std::string listserver_host;
    int listserver_port;
    std::string game_host;
    std::string account;
    std::string password;
    std::vector<grc::ServerInfo> servers;
    SOCKET game_socket;
    SOCKET nc_socket;
    grc::GRCProtocol protocol;
    grc::NCProtocol nc_protocol;
    std::thread recv_thread;
    std::thread nc_recv_thread;
    std::atomic<bool> running;
    std::atomic<bool> connected;
    std::atomic<bool> authenticated;
    std::atomic<bool> nc_connected;
    std::atomic<bool> nc_authenticated;
    std::atomic<bool> is_new_protocol;
    std::mutex callback_mutex;
    std::mutex error_mutex;
    std::mutex cache_mutex;
    std::string last_error;
    std::string npc_server_address;
    int npcserver_player_id;
    std::vector<RCServer> server_cache;
    std::vector<RCPlayer> player_cache;
    std::vector<RCWeapon> weapon_cache;
    std::vector<RCClass> class_cache;
    std::vector<RCNPC> npc_cache;
    std::vector<RCLevel> level_cache;
    std::vector<std::string> pm_server_cache;
    std::vector<const char*> pm_server_ptr_cache;
    std::map<int, std::string> npc_flags_cache;
    std::vector<FileBrowserFolderCacheEntry> filebrowser_folders;
    std::vector<RCFileBrowserFolder> filebrowser_folder_view;
    std::vector<FileBrowserFileCacheEntry> filebrowser_files;
    std::vector<RCFileBrowserEntry> filebrowser_file_view;
    std::string filebrowser_current_folder;
    struct FileTransfer {
        std::vector<uint8_t> buffer;
        size_t size;
        size_t received;
    };
    std::map<std::string, FileTransfer> file_transfers;
    std::string pending_file_download;
    int pending_npc_attributes_id;
    std::mutex transfer_mutex;
    std::queue<std::pair<std::string, std::function<void()>>> event_queue;
    std::mutex event_mutex;
    RC_OnConnected on_connected;
    void* on_connected_data;
    RC_OnDisconnected on_disconnected;
    void* on_disconnected_data;
    RC_OnPlayerJoined on_player_joined;
    void* on_player_joined_data;
    RC_OnPlayerLeft on_player_left;
    void* on_player_left_data;
    RC_OnMessage on_message;
    void* on_message_data;
    RC_OnPrivateMessage on_private_message;
    void* on_private_message_data;
    RC_OnFileReceived on_file_received;
    void* on_file_received_data;
    RC_OnWeaponAdded on_weapon_added;
    void* on_weapon_added_data;
    RC_OnWeaponDeleted on_weapon_deleted;
    void* on_weapon_deleted_data;
    RC_OnClassAdded on_class_added;
    void* on_class_added_data;
    RC_OnClassDeleted on_class_deleted;
    void* on_class_deleted_data;
    RC_OnNPCAdded on_npc_added;
    void* on_npc_added_data;
    RC_OnNPCDeleted on_npc_deleted;
    void* on_npc_deleted_data;
    RC_OnNPCAttributes on_npc_attributes;
    void* on_npc_attributes_data;
    RC_OnPlayerPropChanged on_player_prop_changed;
    void* on_player_prop_changed_data;
    RC_OnWorldTime on_world_time;
    void* on_world_time_data;
    RC_OnMaxUploadFileSize on_max_upload_file_size;
    void* on_max_upload_file_size_data;
    RC_OnCommandResponse on_command_response;
    void* on_command_response_data;
    RC_OnRawPacket on_raw_packet;
    void* on_raw_packet_data;
    RC_OnPMServersUpdated on_pm_servers_updated;
    void* on_pm_servers_updated_data;
    RC_OnNPCFlags on_npc_flags;
    void* on_npc_flags_data;
    RC_OnPMServerPlayers on_pm_server_players;
    void* on_pm_server_players_data;
    RC_OnFileBrowserFolders on_filebrowser_folders;
    void* on_filebrowser_folders_data;
    RC_OnFileBrowserFiles on_filebrowser_files;
    void* on_filebrowser_files_data;
    RC_OnFileBrowserMessage on_filebrowser_message;
    void* on_filebrowser_message_data;
    RC_OnScriptReceived on_script_received;
    void* on_script_received_data;
    RC_OnServerData on_server_data;
    void* on_server_data_data;
    RC_OnPlayerRights on_player_rights;
    void* on_player_rights_data;
    RC_OnPlayerTextData on_player_text_data;
    void* on_player_text_data_data;
    RC_OnPlayerAttributes on_player_attributes;
    void* on_player_attributes_data;
    RC_OnLocalNPCs on_local_npcs;
    void* on_local_npcs_data;
    RC_OnIrcMessage on_irc_message;
    void* on_irc_message_data;
    RC_OnBanData on_ban_data;
    void* on_ban_data_data;
    RC_OnBanListData on_ban_list_data;
    void* on_ban_list_data_data;
    RC_OnAccountList on_account_list;
    void* on_account_list_data;
    std::string pending_local_npcs_level;
    std::string pending_ban_account;
    int pending_ban_player_id;
    std::string server_options;
    std::string server_flags;
    std::string folder_config;
    long long max_upload_file_size;
    RCConnection() : game_socket(INVALID_SOCKET), nc_socket(INVALID_SOCKET), running(false), connected(false), authenticated(false), nc_connected(false), nc_authenticated(false), is_new_protocol(false), npcserver_player_id(0),
        on_connected(nullptr), on_connected_data(nullptr), on_disconnected(nullptr), on_disconnected_data(nullptr),
        on_player_joined(nullptr), on_player_joined_data(nullptr), on_player_left(nullptr), on_player_left_data(nullptr),
        on_message(nullptr), on_message_data(nullptr), on_private_message(nullptr), on_private_message_data(nullptr), on_file_received(nullptr), on_file_received_data(nullptr),
        on_weapon_added(nullptr), on_weapon_added_data(nullptr), on_weapon_deleted(nullptr), on_weapon_deleted_data(nullptr),
        on_class_added(nullptr), on_class_added_data(nullptr), on_class_deleted(nullptr), on_class_deleted_data(nullptr),
        on_npc_added(nullptr), on_npc_added_data(nullptr), on_npc_deleted(nullptr), on_npc_deleted_data(nullptr),
        on_npc_attributes(nullptr), on_npc_attributes_data(nullptr),
        on_player_prop_changed(nullptr), on_player_prop_changed_data(nullptr), on_world_time(nullptr), on_world_time_data(nullptr),
        on_max_upload_file_size(nullptr), on_max_upload_file_size_data(nullptr), on_command_response(nullptr), on_command_response_data(nullptr),
        on_raw_packet(nullptr), on_raw_packet_data(nullptr), on_pm_servers_updated(nullptr), on_pm_servers_updated_data(nullptr),
        on_npc_flags(nullptr), on_npc_flags_data(nullptr), on_pm_server_players(nullptr), on_pm_server_players_data(nullptr),
        on_filebrowser_folders(nullptr), on_filebrowser_folders_data(nullptr),
        on_filebrowser_files(nullptr), on_filebrowser_files_data(nullptr), on_filebrowser_message(nullptr), on_filebrowser_message_data(nullptr),
        on_script_received(nullptr), on_script_received_data(nullptr), on_server_data(nullptr), on_server_data_data(nullptr),
        on_player_rights(nullptr), on_player_rights_data(nullptr), on_player_text_data(nullptr), on_player_text_data_data(nullptr),
        on_player_attributes(nullptr), on_player_attributes_data(nullptr), on_local_npcs(nullptr), on_local_npcs_data(nullptr),
        on_irc_message(nullptr), on_irc_message_data(nullptr), on_ban_data(nullptr), on_ban_data_data(nullptr),
        on_ban_list_data(nullptr), on_ban_list_data_data(nullptr), on_account_list(nullptr), on_account_list_data(nullptr), pending_npc_attributes_id(-1), pending_ban_player_id(-1), max_upload_file_size(0) {}
    void setError(const std::string& err) {
        std::lock_guard<std::mutex> lock(error_mutex);
        last_error = err;
    }
    std::string getError() {
        std::lock_guard<std::mutex> lock(error_mutex);
        return last_error;
    }
    void pushEvent(std::function<void()> callback, const std::string& label = "event") {
        std::lock_guard<std::mutex> lock(event_mutex);
        event_queue.push(std::make_pair(label, callback));
    }
    void clearFileBrowserFolderView() {
        for (auto& item : filebrowser_folder_view) {
            if (item.rights) free((void*)item.rights);
            if (item.pattern) free((void*)item.pattern);
        }
        filebrowser_folder_view.clear();
    }
    void clearFileBrowserFileView() {
        for (auto& item : filebrowser_file_view) {
            if (item.path) free((void*)item.path);
            if (item.rights) free((void*)item.rights);
        }
        filebrowser_file_view.clear();
    }
    void updateCachedPlayerProp(int player_id, const PlayerPropValue& prop) {
        if (prop.name != "account" && prop.name != "nick" && prop.name != "level") return;
        std::lock_guard<std::mutex> lock(cache_mutex);
        for (auto& player : player_cache) {
            if (player.id != player_id) continue;
            if (prop.name == "account") {
                if (player.account) free(player.account);
                player.account = grcStrdup(prop.value.c_str());
            } else if (prop.name == "nick") {
                if (player.nick) free(player.nick);
                player.nick = grcStrdup(prop.value.c_str());
            } else if (prop.name == "level") {
                if (player.level) free(player.level);
                player.level = prop.value.empty() ? nullptr : grcStrdup(prop.value.c_str());
            }
            return;
        }
    }
    void emitPlayerPropChanged(int player_id, const PlayerPropValue& prop) {
        if (!on_player_prop_changed) return;
        pushEvent([this, player_id, name = prop.name, value = prop.value]() {
            on_player_prop_changed(player_id, name.c_str(), value.c_str(), on_player_prop_changed_data);
        });
    }
    void processPacket(const std::vector<uint8_t>& packet) {
        if (packet.empty()) return;
        uint8_t packet_id = grc::decodeGByte(packet[0]);
        size_t offset = 1;
        auto emitServerDataPacket = [&](const char* data_type, size_t start_offset) {
            if (!on_server_data) return;
            if (start_offset > packet.size()) start_offset = packet.size();
            std::string content(packet.begin() + start_offset, packet.end());
            pushEvent([this, data_type = std::string(data_type), content]() {
                on_server_data(data_type.c_str(), content.c_str(), on_server_data_data);
            });
        };

        // Game server INCOMING packets (ServerToPlayer / PLO_)
        switch (packet_id) {
            case PLO_LEVELBOARD: { // 0
                break;
            }
            case PLO_SIGNATURE: { // 25 - Authentication success
                if (!authenticated) {
                    authenticated = true;
                    if (on_connected) pushEvent([this]() { on_connected(on_connected_data); });
                }
                break;
            }
            case PLO_UNKNOWN190: { // RC ready
                sendListerText(this, "bantypes", "", PLI_REQUESTTEXT);
                break;
            }
            case PLO_DISCMESSAGE: { // 16 - Disconnect message
                std::string disconnect_msg(packet.begin() + offset, packet.end());
                if (on_disconnected) {
                    pushEvent([this, disconnect_msg]() {
                        on_disconnected(disconnect_msg.c_str(), on_disconnected_data);
                    });
                }
                running = false;
                break;
            }
            case PLO_FILESENDFAILED: { // 30 - File download/upload failure
                std::string message(packet.begin() + offset, packet.end());
                if (on_filebrowser_message) {
                    pushEvent([this, message]() {
                        on_filebrowser_message(message.c_str(), on_filebrowser_message_data);
                    });
                }
                break;
            }
            case PLO_FILEUPTODATE: { // 45 - File download complete in RC file-browser transfers
                std::string filename(packet.begin() + offset, packet.end());
                size_t newline_pos = filename.find('\n');
                if (newline_pos != std::string::npos) filename = filename.substr(0, newline_pos);

                std::string transfer_key;
                std::string content;
                {
                    std::lock_guard<std::mutex> lock(transfer_mutex);
                    if (!pending_file_download.empty() && file_transfers.count(pending_file_download)) {
                        transfer_key = pending_file_download;
                    } else if (file_transfers.count(filename)) {
                        transfer_key = filename;
                    } else if (!filename.empty()) {
                        size_t slash = filename.find_last_of("/\\");
                        std::string basename = slash == std::string::npos ? filename : filename.substr(slash + 1);
                        for (const auto& pair : file_transfers) {
                            size_t key_slash = pair.first.find_last_of("/\\");
                            std::string key_basename = key_slash == std::string::npos ? pair.first : pair.first.substr(key_slash + 1);
                            if (key_basename == basename) {
                                transfer_key = pair.first;
                                break;
                            }
                        }
                    } else if (file_transfers.size() == 1) {
                        transfer_key = file_transfers.begin()->first;
                    }
                    if (!transfer_key.empty() && file_transfers[transfer_key].received > 0) {
                        auto& transfer = file_transfers[transfer_key];
                        content.assign(reinterpret_cast<const char*>(transfer.buffer.data()), transfer.buffer.size());
                        file_transfers.erase(transfer_key);
                    }
                    if (!pending_file_download.empty() && (filename.empty() || pending_file_download == filename || pending_file_download == transfer_key)) {
                        pending_file_download.clear();
                    }
                }

                if (!transfer_key.empty() && !content.empty()) {
                    if (on_filebrowser_message) {
                        std::string msg = "File complete: " + transfer_key;
                        pushEvent([this, msg]() { on_filebrowser_message(msg.c_str(), on_filebrowser_message_data); }, "filebrowser_message:file_complete");
                    }
                    if (on_file_received) {
                        pushEvent([this, transfer_key, content]() {
                            on_file_received(transfer_key.c_str(), content.c_str(), content.length(), on_file_received_data);
                        }, "file_received:file_complete:" + transfer_key);
                    }
                }
                break;
            }
            case PLO_BOMBADD: {
                emitServerDataPacket("bombadd", offset);
                break;
            }
            case PLO_RC_ADMINMESSAGE: { // 35 - Administrator popup/message
                std::string message(packet.begin() + offset, packet.end());
                std::replace(message.begin(), message.end(), '\xa7', '\n');
                if (on_server_data) {
                    pushEvent([this, message]() {
                        on_server_data("admin_message", message.c_str(), on_server_data_data);
                    });
                }
                break;
            }
            case PLO_STAFFGUILDS: {
                emitServerDataPacket("staffguilds", offset);
                break;
            }
            case PLO_RC_ACCOUNTADD:
            case PLO_RC_ACCOUNTSTATUS:
            case PLO_RC_ACCOUNTNAME:
            case PLO_RC_ACCOUNTDEL:
            case PLO_RC_ACCOUNTPROPS:
            case PLO_RC_ACCOUNTPROPSGET:
            case PLO_RC_ACCOUNTCHANGE:
            case PLO_RC_PLAYERPROPSCHANGE:
            case PLO_UNKNOWN60:
            case PLO_RC_PLAYERPROPS: {
                emitServerDataPacket(incomingRcPacketName(packet_id), offset);
                break;
            }
            case PLO_RC_ACCOUNTLISTGET: {
                size_t parse_offset = offset;
                std::vector<std::string> accounts;
                while (parse_offset < packet.size()) {
                    std::string account = grc::readLengthString(packet, parse_offset);
                    if (!account.empty()) accounts.push_back(account);
                }
                std::sort(accounts.begin(), accounts.end(), [](const std::string& a, const std::string& b) {
                    std::string aa = a, bb = b;
                    std::transform(aa.begin(), aa.end(), aa.begin(), [](unsigned char c) { return (char)std::tolower(c); });
                    std::transform(bb.begin(), bb.end(), bb.begin(), [](unsigned char c) { return (char)std::tolower(c); });
                    return aa < bb;
                });
                std::string content;
                for (size_t i = 0; i < accounts.size(); ++i) {
                    if (i) content += "\n";
                    content += accounts[i];
                }
                if (on_account_list) {
                    pushEvent([this, content]() {
                        on_account_list(content.c_str(), on_account_list_data);
                    });
                }
                if (on_server_data) {
                    pushEvent([this, content]() {
                        on_server_data("account_list", content.c_str(), on_server_data_data);
                    });
                }
                break;
            }
            case PLO_NPCSERVERADDR: { // 79 - NPC server address
                if (offset + 2 <= packet.size()) {
                    int npc_server_id = grc::decodeGShort(packet.data() + offset) - 0x1020;
                    offset += 2;
                    std::string npc_addr(packet.begin() + offset, packet.end());
                    npc_server_address = npc_addr;
                }
                break;
            }
            case PLO_RC_CHAT: { // 74 - RC chat message
                std::string message(packet.begin() + offset, packet.end());
                message = grc::replaceAll(message, " of +", " of ");
                if (on_message) pushEvent([this, message]() { on_message(message.c_str(), on_message_data); });
                if (on_raw_packet) {
                    std::vector<uint8_t> payload(packet.begin() + offset, packet.end());
                    pushEvent([this, packet_id, payload]() {
                        on_raw_packet(packet_id, (const char*)payload.data(), payload.size(), on_raw_packet_data);
                    });
                }
                break;
            }
            case PLO_PROFILE: { // 75 - Player profile
                size_t parse_offset = offset;
                std::vector<std::string> fields;
                while (parse_offset < packet.size()) {
                    fields.push_back(grc::readLengthString(packet, parse_offset));
                }
                std::string account = fields.empty() ? "" : fields[0];
                std::string content;
                for (size_t i = 0; i < fields.size(); ++i) {
                    if (i > 0) content += "\n";
                    content += fields[i];
                }
                if (on_player_text_data) {
                    pushEvent([this, account, content]() {
                        on_player_text_data("profile", account.c_str(), content.c_str(), on_player_text_data_data);
                    });
                }
                if (on_raw_packet) {
                    std::vector<uint8_t> payload(packet.begin() + offset, packet.end());
                    pushEvent([this, packet_id, payload]() {
                        on_raw_packet(packet_id, (const char*)payload.data(), payload.size(), on_raw_packet_data);
                    });
                }
                break;
            }
            case PLO_RC_PLAYERBANGET: { // 64 - Legacy player ban response
                std::string account = pending_ban_account;
                std::string details;
                if (offset < packet.size()) {
                    size_t parse_offset = offset;
                    std::string parsed_account = grc::readLengthString(packet, parse_offset);
                    if (!parsed_account.empty()) account = parsed_account;
                    details.assign(packet.begin() + offset, packet.end());
                }
                if (on_ban_data) {
                    pushEvent([this, account, details]() {
                        on_ban_data(account.c_str(), "", details.c_str(), on_ban_data_data);
                    });
                }
                pending_ban_account.clear();
                pending_ban_player_id = -1;
                break;
            }
            case PLO_OTHERPLPROPS: { // 8 - Other player properties (nickname change, etc)
                if (offset + 2 <= packet.size()) {
                    int player_id = grc::decodeGShort(packet.data() + offset);
                    offset += 2;
                    while (offset < packet.size()) {
                        int prop_id = grc::decodeGByte(packet[offset++]);
                        PlayerPropValue prop;
                        if (!readPlayerPropValue(packet, offset, prop_id, prop)) break;
                        updateCachedPlayerProp(player_id, prop);
                        emitPlayerPropChanged(player_id, prop);
                    }
                }
                break;
            }
            case PLO_TOALL: { // 13 - To All message
                if (offset + 2 <= packet.size()) {
                    int player_id = grc::decodeGShort(packet.data() + offset);
                    offset += 2;
                    if (offset < packet.size()) {
                        int message_len = grc::decodeGByte(packet[offset++]);
                        if (offset + message_len <= packet.size()) {
                            std::string message(packet.begin() + offset, packet.begin() + offset + message_len);
                            if (on_server_data) {
                                pushEvent([this, message]() {
                                    on_server_data("toall", message.c_str(), on_server_data_data);
                                });
                            }
                        }
                    }
                }
                break;
            }
            case PLO_RC_PLAYERPROPSGET: { // 72 - Player properties response (massive 87 properties!)
                if (packet.size() > offset + 4 && on_player_attributes) {
                    size_t parse_offset = offset;
                    parse_offset += 2; // player id, currently only used by the server response envelope
                    std::string account = readAttrString(packet, parse_offset);
                    std::string world = readAttrString(packet, parse_offset);
                    int props_len = (parse_offset < packet.size()) ? decodeAttrByte(packet[parse_offset++]) : 0;
                    size_t props_end = parse_offset + props_len;
                    if (props_end > packet.size()) props_end = packet.size();

                    std::ostringstream properties;
                    bool first_property = true;
                    properties << "{";
                    jsonAddString(properties, first_property, "account", account);
                    jsonAddString(properties, first_property, "world", world);

                    while (parse_offset < props_end && parse_offset < packet.size()) {
                        int prop_id = decodeAttrByte(packet[parse_offset++]);

                        if (prop_id == 0) {
                            jsonAddString(properties, first_property, "nickname", readAttrString(packet, parse_offset));
                        } else if (prop_id == 1 || prop_id == 4 || prop_id == 5 || prop_id == 6 ||
                                   prop_id == 7 || prop_id == 17 || prop_id == 18 || prop_id == 19 ||
                                   prop_id == 22 || prop_id == 26 || prop_id == 32 || prop_id == 33 ||
                                   prop_id == 43 || prop_id == 44 || prop_id == 50 || prop_id == 51 ||
                                   prop_id == 81) {
                            if (parse_offset < packet.size()) {
                                jsonAddNumber(properties, first_property, std::to_string(prop_id), decodeAttrByte(packet[parse_offset++]));
                            }
                        } else if (prop_id == 53) {
                            jsonAddString(properties, first_property, "status_message", readAttrString(packet, parse_offset));
                        } else if (prop_id == 2 || prop_id == 15 || prop_id == 16) {
                            if (parse_offset < packet.size()) {
                                jsonAddNumber(properties, first_property, std::to_string(prop_id), decodeAttrByte(packet[parse_offset++]) / 2.0);
                            }
                        } else if (prop_id == 3 || prop_id == 27 || prop_id == 28 || prop_id == 29) {
                            if (parse_offset + 2 < packet.size()) {
                                int b0 = decodeAttrByte(packet[parse_offset]);
                                int b1 = decodeAttrByte(packet[parse_offset + 1]);
                                int b2 = decodeAttrByte(packet[parse_offset + 2]);
                                jsonAddNumber(properties, first_property, std::to_string(prop_id), (b0 << 14) + (b1 << 7) + b2);
                                parse_offset += 3;
                            } else {
                                parse_offset = packet.size();
                            }
                        } else if (prop_id == 8) {
                            int power = (parse_offset < packet.size()) ? decodeAttrByte(packet[parse_offset++]) : 0;
                            if (power >= 10) {
                                std::string image = readAttrString(packet, parse_offset);
                                jsonAddNumber(properties, first_property, "sword_power", image.empty() ? power : power - 30);
                                jsonAddString(properties, first_property, "sword_image", image);
                            } else if (power != 0) {
                                jsonAddNumber(properties, first_property, "sword_power", power);
                                jsonAddString(properties, first_property, "sword_image", "sword" + std::to_string(power) + ".gif");
                            } else {
                                jsonAddNumber(properties, first_property, "sword_power", 0);
                                jsonAddString(properties, first_property, "sword_image", "");
                            }
                        } else if (prop_id == 9) {
                            int power = (parse_offset < packet.size()) ? decodeAttrByte(packet[parse_offset++]) : 0;
                            if (power >= 10) {
                                std::string image = readAttrString(packet, parse_offset);
                                jsonAddNumber(properties, first_property, "shield_power", power - 10);
                                jsonAddString(properties, first_property, "shield_image", image);
                            } else if (power != 0) {
                                jsonAddNumber(properties, first_property, "shield_power", power);
                                jsonAddString(properties, first_property, "shield_image", "shield" + std::to_string(power) + ".gif");
                            } else {
                                jsonAddNumber(properties, first_property, "shield_power", 0);
                                jsonAddString(properties, first_property, "shield_image", "");
                            }
                        } else if (prop_id == 11) {
                            if (parse_offset < packet.size()) {
                                int head_len = decodeAttrByte(packet[parse_offset++]);
                                if (head_len > 0 && head_len < 100) {
                                    jsonAddString(properties, first_property, "head_image", "head" + std::to_string(head_len) + ".gif");
                                } else if (head_len >= 100 && parse_offset + (size_t)(head_len - 100) <= packet.size()) {
                                    std::string image(packet.begin() + parse_offset, packet.begin() + parse_offset + (head_len - 100));
                                    jsonAddString(properties, first_property, "head_image", image);
                                    parse_offset += head_len - 100;
                                } else {
                                    jsonAddString(properties, first_property, "head_image", "head0.gif");
                                }
                            }
                        } else if (prop_id == 13) {
                            if (parse_offset + 4 < packet.size()) {
                                std::vector<int> colors;
                                for (int i = 0; i < 5; ++i) colors.push_back(decodeAttrByte(packet[parse_offset + i]));
                                jsonAddIntArray(properties, first_property, "colors", colors);
                                parse_offset += 5;
                            } else {
                                parse_offset = packet.size();
                            }
                        } else if (isPlayerAttrStringProp(prop_id)) {
                            jsonAddString(properties, first_property, playerPropName(prop_id), readAttrString(packet, parse_offset));
                        } else if (prop_id == 30) {
                            if (parse_offset + 4 < packet.size()) {
                                int b0 = decodeAttrByte(packet[parse_offset]) & 0xff;
                                int b1 = decodeAttrByte(packet[parse_offset + 1]) & 0xff;
                                int b2 = decodeAttrByte(packet[parse_offset + 2]) & 0xff;
                                int b3 = decodeAttrByte(packet[parse_offset + 3]) & 0xff;
                                int b4 = decodeAttrByte(packet[parse_offset + 4]) & 0xff;
                                int ip_value = (b0 << 28) | (b1 << 21) | (b2 << 14) | (b3 << 7) | b4;
                                std::string ip = std::to_string(ip_value & 0xff) + "." +
                                    std::to_string((ip_value >> 8) & 0xff) + "." +
                                    std::to_string((ip_value >> 16) & 0xff) + "." +
                                    std::to_string((ip_value >> 24) & 0xff);
                                jsonAddString(properties, first_property, "last_ip", ip);
                                parse_offset += 5;
                            } else {
                                parse_offset = packet.size();
                            }
                        } else if (prop_id == 36) {
                            if (parse_offset + 2 < packet.size()) {
                                int byte1 = decodeAttrByte(packet[parse_offset]);
                                int byte2 = decodeAttrByte(packet[parse_offset + 1]);
                                int byte3 = decodeAttrByte(packet[parse_offset + 2]);
                                jsonAddNumber(properties, first_property, "rating", (byte1 << 5) + (byte2 >> 2));
                                jsonAddNumber(properties, first_property, "rating_dev", ((byte2 & 0x03) << 7) + byte3);
                                parse_offset += 3;
                            } else {
                                parse_offset = packet.size();
                            }
                        } else if (prop_id == 45) {
                            if (parse_offset < packet.size()) {
                                jsonAddNumber(properties, first_property, playerPropName(prop_id), decodeAttrByte(packet[parse_offset++]) - 50);
                            }
                        } else if (prop_id == 78 || prop_id == 79 || prop_id == 80) {
                            if (parse_offset + 1 < packet.size()) {
                                jsonAddNumber(properties, first_property, playerPropName(prop_id), decodeAttrSigned14(packet, parse_offset));
                                parse_offset += 2;
                            } else {
                                parse_offset = packet.size();
                            }
                        } else if (prop_id == 23) {
                            if (parse_offset < packet.size()) {
                                parse_offset += decodeAttrByte(packet[parse_offset]) > 0 ? 4 : 1;
                            }
                        } else if (prop_id == 24) {
                            parse_offset += 3;
                        } else if (prop_id == 25) {
                            parse_offset += 2;
                        } else if (prop_id == 31 || prop_id == 76) {
                            parse_offset += 3;
                        } else if (prop_id == 42) {
                            parse_offset += 4;
                        } else if (parse_offset < packet.size()) {
                            parse_offset += 1;
                        }
                    }

                    std::vector<std::string> flags;
                    if (parse_offset + 1 < packet.size()) {
                        int flag_count = ((decodeAttrByte(packet[parse_offset]) << 7) + decodeAttrByte(packet[parse_offset + 1]));
                        parse_offset += 2;
                        for (int i = 0; i < flag_count && parse_offset < packet.size(); ++i) {
                            flags.push_back(readAttrString(packet, parse_offset));
                        }
                    }

                    std::vector<std::string> chests;
                    if (parse_offset + 1 < packet.size()) {
                        int chest_count = ((decodeAttrByte(packet[parse_offset]) << 7) + decodeAttrByte(packet[parse_offset + 1]));
                        parse_offset += 2;
                        for (int i = 0; i < chest_count && parse_offset < packet.size(); ++i) {
                            chests.push_back(readAttrString(packet, parse_offset));
                        }
                    }

                    std::vector<std::string> weapons;
                    if (parse_offset < packet.size()) {
                        int weapon_count = decodeAttrByte(packet[parse_offset++]);
                        for (int i = 0; i < weapon_count && parse_offset < packet.size(); ++i) {
                            weapons.push_back(readAttrString(packet, parse_offset));
                        }
                    }

                    jsonAddStringArray(properties, first_property, "flags", flags);
                    jsonAddStringArray(properties, first_property, "chests", chests);
                    jsonAddStringArray(properties, first_property, "weapons", weapons);
                    properties << "}";
                    std::string properties_json = properties.str();
                    char* formatted_text = rc_format_player_attributes_text(properties_json.c_str());
                    std::string editor_text = formatted_text ? formatted_text : "";
                    if (formatted_text) free(formatted_text);
                    pushEvent([this, account, properties_json, editor_text]() {
                        on_player_attributes(account.c_str(), properties_json.c_str(), editor_text.c_str(), on_player_attributes_data);
                    });
                }
                if (on_raw_packet) {
                    std::vector<uint8_t> payload(packet.begin() + offset, packet.end());
                    pushEvent([this, packet_id, payload]() {
                        on_raw_packet(packet_id, (const char*)payload.data(), payload.size(), on_raw_packet_data);
                    });
                }
                break;
            }
            case PLO_RC_ACCOUNTGET: { // 73 - Account info response
                size_t parse_offset = offset;
                std::string account = grc::readLengthString(packet, parse_offset);
                std::string password = grc::readLengthString(packet, parse_offset);
                std::string email = grc::readLengthString(packet, parse_offset);
                int banned = (parse_offset < packet.size()) ? grc::decodeGByte(packet[parse_offset++]) : 0;
                int guest = (parse_offset < packet.size()) ? grc::decodeGByte(packet[parse_offset++]) : 0;
                int admin_level = (parse_offset < packet.size()) ? grc::decodeGByte(packet[parse_offset++]) : 0;
                std::string admin_worlds = grc::readLengthString(packet, parse_offset);
                std::string ban_length = grc::readLengthString(packet, parse_offset);
                std::string ban_reason;
                if (parse_offset < packet.size()) {
                    ban_reason = grc::gtokenizeReverseString(grc::readLengthString(packet, parse_offset));
                }
                std::string content =
                    "account=" + account + "\n" +
                    "password=" + password + "\n" +
                    "email=" + email + "\n" +
                    "banned=" + std::to_string(banned) + "\n" +
                    "guest=" + std::to_string(guest) + "\n" +
                    "admin_level=" + std::to_string(admin_level) + "\n" +
                    "admin_worlds=" + admin_worlds + "\n" +
                    "ban_length=" + ban_length + "\n" +
                    "ban_reason=" + ban_reason;
                if (on_player_text_data) {
                    pushEvent([this, account, content]() {
                        on_player_text_data("account", account.c_str(), content.c_str(), on_player_text_data_data);
                    });
                }
                if (on_raw_packet) {
                    std::vector<uint8_t> payload(packet.begin() + offset, packet.end());
                    pushEvent([this, packet_id, payload]() {
                        on_raw_packet(packet_id, (const char*)payload.data(), payload.size(), on_raw_packet_data);
                    });
                }
                break;
            }
            case PLO_RC_SERVEROPTIONSGET: { // 76 - Server options response
                std::string tokenized(packet.begin() + offset, packet.end());
                std::string content = grc::gtokenizeReverseString(tokenized);
                {
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    server_options = content;
                }
                if (on_server_data) {
                    pushEvent([this, content]() {
                        on_server_data("options", content.c_str(), on_server_data_data);
                    });
                }
                if (on_raw_packet) {
                    std::vector<uint8_t> payload(packet.begin() + offset, packet.end());
                    pushEvent([this, packet_id, payload]() {
                        on_raw_packet(packet_id, (const char*)payload.data(), payload.size(), on_raw_packet_data);
                    });
                }
                break;
            }
            case PLO_RC_FOLDERCONFIGGET: { // 77 - Folder config response
                std::string tokenized(packet.begin() + offset, packet.end());
                std::string content = grc::gtokenizeReverseString(tokenized);
                {
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    folder_config = content;
                }
                if (on_server_data) {
                    pushEvent([this, content]() {
                        on_server_data("folder_config", content.c_str(), on_server_data_data);
                    });
                }
                if (on_raw_packet) {
                    std::vector<uint8_t> payload(packet.begin() + offset, packet.end());
                    pushEvent([this, packet_id, payload]() {
                        on_raw_packet(packet_id, (const char*)payload.data(), payload.size(), on_raw_packet_data);
                    });
                }
                break;
            }
            case PLO_ADDPLAYER: { // 55 - Player join with full properties!
                if (offset + 2 <= packet.size()) {
                    int player_id = grc::decodeGShort(packet.data() + offset);
                    offset += 2;
                    if (offset < packet.size()) {
                        int account_len = grc::decodeGByte(packet[offset++]);
                        if (offset + account_len <= packet.size()) {
                            std::string account(packet.begin() + offset, packet.begin() + offset + account_len);
                            offset += account_len;
                            if (account.find("(npcserver)") != std::string::npos) {
                                npcserver_player_id = player_id;
                                std::vector<uint8_t> query_data;
                                grc::writeGShort(query_data, player_id);
                                query_data.insert(query_data.end(), {'l','o','c','a','t','i','o','n'});
                                std::vector<uint8_t> query_packet = protocol.sendPacket(PLI_NPCSERVERQUERY, query_data);
                                grc::sendAll(game_socket, query_packet.data(), query_packet.size());
                            }
                            // Parse the same player property stream used by live property updates.
                            std::string nickname, level;
                            std::string account_from_props;
                            std::vector<PlayerPropValue> parsed_props;
                            while (offset < packet.size()) {
                                int prop_id = grc::decodeGByte(packet[offset++]);
                                PlayerPropValue prop;
                                if (!readPlayerPropValue(packet, offset, prop_id, prop)) break;
                                if (prop.name == "nick") nickname = prop.value;
                                else if (prop.name == "level") level = prop.value;
                                else if (prop.name == "account") account_from_props = prop.value;
                                parsed_props.push_back(prop);
                            }
                            if (!account_from_props.empty()) account = account_from_props;
                            {
                                std::lock_guard<std::mutex> lock(cache_mutex);
                                bool found = false;
                                for (auto& p : player_cache) {
                                    if (p.id == player_id) {
                                        if (p.account) free(p.account);
                                        if (p.nick) free(p.nick);
                                        if (p.level) free(p.level);
                                        p.account = grcStrdup(account.c_str());
                                        p.nick = grcStrdup(nickname.c_str());
                                        p.level = level.empty() ? nullptr : grcStrdup(level.c_str());
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    RCPlayer player;
                                    player.account = grcStrdup(account.c_str());
                                    player.id = player_id;
                                    player.nick = grcStrdup(nickname.c_str());
                                    player.level = level.empty() ? nullptr : grcStrdup(level.c_str());
                                    player_cache.push_back(player);
                                }
                            }
                            for (const auto& prop : parsed_props) emitPlayerPropChanged(player_id, prop);
                            if (on_player_joined) {
                                pushEvent([this, account, player_id]() {
                                    on_player_joined(account.c_str(), player_id, on_player_joined_data);
                                });
                            }
                        }
                    }
                }
                break;
            }
            case PLO_DELPLAYER: { // 56 - Player leave
                if (offset + 2 <= packet.size()) {
                    int player_id = grc::decodeGShort(packet.data() + offset);
                    offset += 2;
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    for (auto it = player_cache.begin(); it != player_cache.end(); ++it) {
                        if (it->id == player_id) {
                            if (it->account) free(it->account);
                            if (it->nick) free(it->nick);
                            if (it->level) free(it->level);
                            player_cache.erase(it);
                            break;
                        }
                    }
                    if (on_player_left) {
                        pushEvent([this, player_id]() {
                            on_player_left("", player_id, on_player_left_data);
                        });
                    }
                }
                break;
            }
            case PLO_RC_SERVERFLAGSGET: { // 61 - Server flags response
                if (offset + 2 <= packet.size()) {
                    int num_flags = grc::decodeGShort(packet.data() + offset);
                    offset += 2;
                    std::vector<std::string> flags;
                    for (int i = 0; i < num_flags && offset < packet.size(); ++i) {
                        int flag_len = grc::decodeGByte(packet[offset++]);
                        if (offset + flag_len <= packet.size()) {
                            std::string flag(packet.begin() + offset, packet.begin() + offset + flag_len);
                            flags.push_back(flag);
                            offset += flag_len;
                        }
                    }
                    server_flags.clear();
                    for (const auto& flag : flags) {
                        server_flags += flag + "\n";
                    }
                    std::string content = server_flags;
                    if (on_server_data) {
                        pushEvent([this, content]() {
                            on_server_data("flags", content.c_str(), on_server_data_data);
                        });
                    }
                    if (on_raw_packet) {
                        std::vector<uint8_t> payload(packet.begin() + 1, packet.end());
                        pushEvent([this, packet_id, payload]() {
                            on_raw_packet(packet_id, (const char*)payload.data(), payload.size(), on_raw_packet_data);
                        });
                    }
                }
                break;
            }
            case PLO_RC_PLAYERRIGHTSGET: { // 62 - Player rights response
                size_t parse_offset = offset;
                std::string account = grc::readLengthString(packet, parse_offset);
                int rights_value = grc::readGInt5(packet, parse_offset);
                std::string ip_range = grc::readLengthString(packet, parse_offset);
                std::string folder_access;
                if (parse_offset + 2 <= packet.size()) {
                    int folder_len = grc::decodeGShort(packet.data() + parse_offset);
                    parse_offset += 2;
                    folder_access = grc::readCommaText(packet, parse_offset, folder_len);
                }
                if (on_player_rights) {
                    pushEvent([this, account, rights_value, ip_range, folder_access]() {
                        on_player_rights(account.c_str(), rights_value, ip_range.c_str(), folder_access.c_str(), on_player_rights_data);
                    });
                }
                if (on_raw_packet) {
                    std::vector<uint8_t> payload(packet.begin() + offset, packet.end());
                    pushEvent([this, packet_id, payload]() {
                        on_raw_packet(packet_id, (const char*)payload.data(), payload.size(), on_raw_packet_data);
                    });
                }
                break;
            }
            case PLO_RC_PLAYERCOMMENTSGET: { // 63 - Player comments response
                size_t parse_offset = offset;
                std::string account = grc::readLengthString(packet, parse_offset);
                std::string comments = grc::readCommaText(packet, parse_offset);
                if (on_player_text_data) {
                    pushEvent([this, account, comments]() {
                        on_player_text_data("comments", account.c_str(), comments.c_str(), on_player_text_data_data);
                    });
                }
                if (on_raw_packet) {
                    std::vector<uint8_t> payload(packet.begin() + offset, packet.end());
                    pushEvent([this, packet_id, payload]() {
                        on_raw_packet(packet_id, (const char*)payload.data(), payload.size(), on_raw_packet_data);
                    });
                }
                break;
            }
            case PLO_RC_FILEBROWSER_DIRLIST: { // 65 - Folder list response
                if (on_filebrowser_message) {
                    pushEvent([this]() {
                        on_filebrowser_message("Received file browser folder-list packet", on_filebrowser_message_data);
                    });
                }
                std::string folder_list = grc::readCommaText(packet, offset);
                std::vector<FileBrowserFolderCacheEntry> folders;
                for (const auto& raw_line : splitText(folder_list, '\n')) {
                    std::string line = trimText(raw_line);
                    if (line.empty()) continue;
                    size_t split_pos = line.find(' ');
                    if (split_pos == std::string::npos) continue;
                    FileBrowserFolderCacheEntry entry;
                    entry.rights = line.substr(0, split_pos);
                    entry.pattern = trimText(line.substr(split_pos + 1));
                    if (!entry.pattern.empty()) folders.push_back(entry);
                }
                int count = static_cast<int>(folders.size());
                {
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    filebrowser_folders = folders;
                }
                if (on_filebrowser_folders) {
                    pushEvent([this, count]() {
                        on_filebrowser_folders(count, on_filebrowser_folders_data);
                    }, "filebrowser_folders");
                }
                if (on_filebrowser_message) {
                    std::string msg = "Received " + std::to_string(count) + " folders";
                    pushEvent([this, msg]() {
                        on_filebrowser_message(msg.c_str(), on_filebrowser_message_data);
                    });
                }
                break;
            }
            case PLO_RC_FILEBROWSER_DIR: { // 66 - File listing response (with compression/encryption!)
                if (on_filebrowser_message) {
                    pushEvent([this]() {
                        on_filebrowser_message("Received file browser directory packet", on_filebrowser_message_data);
                    });
                }
                if (packet.size() == offset || (packet.size() == offset + 1 && packet[offset] == 0x20)) {
                    {
                        std::lock_guard<std::mutex> lock(cache_mutex);
                        filebrowser_files.clear();
                    }
                    if (on_filebrowser_files) {
                        pushEvent([this]() {
                            on_filebrowser_files("", 0, on_filebrowser_files_data);
                        }, "filebrowser_files:empty");
                    }
                    break;
                }
                std::vector<uint8_t> payload(packet.begin() + offset, packet.end());
                if (payload.size() >= 2 && payload[0] == 'Z' && payload[1] == 'h') {
                    std::vector<uint8_t> temp = {0x42};
                    temp.insert(temp.end(), payload.begin(), payload.end());
                    payload = grc::bzip2Decompress(temp.data(), temp.size());
                } else if (payload.size() >= 2 && payload[0] == 0x1f && payload[1] == 0x8b) {
                    std::vector<uint8_t> decompressed;
                    mz_ulong dest_len = payload.size() * 10;
                    decompressed.resize(dest_len);
                    if (mz_uncompress(decompressed.data(), &dest_len, payload.data(), payload.size()) == MZ_OK) {
                        decompressed.resize(dest_len);
                        payload = decompressed;
                    }
                } else {
                    int first_byte = (payload[0] - 32) & 0xFF;
                    int format_type = -1;
                    if (first_byte <= 5) {
                        size_t potential_path_len = first_byte;
                        bool is_plain = false;
                        if (potential_path_len > 0 && payload.size() > potential_path_len + 1) {
                            std::vector<uint8_t> potential_path(payload.begin() + 1, payload.begin() + 1 + potential_path_len);
                            bool all_printable = true;
                            for (auto b : potential_path) {
                                if (b < 32 || b > 126) {all_printable = false;break;}
                            }
                            if (all_printable) is_plain = true;
                        }
                        if (!is_plain) format_type = first_byte;
                    }
                    if (format_type == 1 || format_type == 3 || format_type == 5) {
                        std::vector<uint8_t> original_payload_after_format(payload.begin() + 1, payload.end());
                        uint32_t mask = 0x04A80B38;
                        uint32_t seed = protocol.encryption_key;
                        uint32_t MASK_ROTATION = 0x08088405;
                        std::vector<int> rotation_counts = (format_type == 5) ? std::vector<int>{4,8,12,16,20,24} : std::vector<int>{(format_type == 1) ? 12 : 4};
                        std::vector<uint8_t> best_payload;
                        for (int rotations : rotation_counts) {
                            std::vector<uint8_t> result = original_payload_after_format;
                            mask = 0x04A80B38;
                            size_t off = 0;
                            while (off < 4 * rotations && off < result.size()) {
                                mask = (mask * MASK_ROTATION + seed) & 0xFFFFFFFF;
                                for (size_t idx = off; idx < off + 4 && idx < result.size(); ++idx) {
                                    uint8_t byte_mask = (mask >> (8 * (idx % 4))) & 0xFF;
                                    result[idx] = original_payload_after_format[idx] ^ byte_mask;
                                }
                                off += 4;
                            }
                            if (result.size() > 0) {
                                uint8_t fb = result[0];
                                if ((fb >= 32 && fb <= 127) || (fb == 0x0a || fb == 0x0d)) {
                                    best_payload = result;
                                    break;
                                }
                            }
                        }
                        if (!best_payload.empty()) payload = best_payload;
                    }
                    if (format_type == 2 || format_type == 3) {
                        std::vector<uint8_t> decompressed;
                        mz_ulong dest_len = payload.size() * 10;
                        decompressed.resize(dest_len);
                        if (mz_uncompress(decompressed.data(), &dest_len, payload.data(), payload.size()) == MZ_OK) {
                            decompressed.resize(dest_len);
                            payload = decompressed;
                        }
                    } else if (format_type == 4 || format_type == 5) {
                        if (payload.size() > 0 && (payload[0] == 0x0a || payload[0] == 0x0d)) {
                            std::vector<uint8_t> temp(payload.begin() + 1, payload.end());
                            if (temp.size() >= 2 && ((temp[0] == 'B' && temp[1] == 'Z') || (temp[0] == 'Z' && temp[1] == 'h'))) {
                                if (temp[0] == 'Z' && temp[1] == 'h') {
                                    std::vector<uint8_t> with_header = {0x42};
                                    with_header.insert(with_header.end(), temp.begin(), temp.end());
                                    temp = with_header;
                                }
                                payload = grc::bzip2Decompress(temp.data(), temp.size());
                            }
                        } else {
                            payload = grc::bzip2Decompress(payload.data(), payload.size());
                        }
                    }
                }
                if (payload.empty()) break;
                if (payload[0] == 132) {
                    if (payload.size() < 5) break;
                    int raw_length = ((payload[1] - 32) << 14) + ((payload[2] - 32) << 7) + (payload[3] - 32);
                    if (raw_length < 0 || payload.size() < 5 + static_cast<size_t>(raw_length)) break;
                    payload = std::vector<uint8_t>(payload.begin() + 5, payload.begin() + 5 + raw_length);
                    if (!payload.empty() && payload.back() == 0x0A) payload.pop_back();
                }
                if (!payload.empty() && payload[0] == grc::writeGByte(PLO_LARGEFILESTART)) {
                    std::vector<uint8_t> filename_bytes(payload.begin() + 1, payload.end());
                    size_t name_end = 0;
                    while (name_end < filename_bytes.size() &&
                           filename_bytes[name_end] != 0 &&
                           filename_bytes[name_end] != '\n' &&
                           filename_bytes[name_end] != '\r') {
                        ++name_end;
                    }
                    std::string filename(filename_bytes.begin(), filename_bytes.begin() + name_end);
                    std::string full_path;
                    {
                        std::lock_guard<std::mutex> lock(transfer_mutex);
                        pending_file_download = filename;
                        full_path = pending_file_download.empty() ? filename : pending_file_download;
                    }
                    size_t content_offset = 1 + name_end + 1;
                    if (content_offset < payload.size()) {
                        std::vector<uint8_t> remaining(payload.begin() + content_offset, payload.end());
                        std::vector<uint8_t> actual_content;
                        if (!remaining.empty() && remaining[0] == grc::writeGByte(PLO_FILE) && remaining.size() >= 7) {
                            size_t embedded_offset = 1 + 5;
                            int embedded_name_len = grc::decodeGByte(remaining[embedded_offset++]);
                            if (embedded_name_len >= 0 && embedded_offset + static_cast<size_t>(embedded_name_len) <= remaining.size()) {
                                embedded_offset += embedded_name_len;
                                actual_content.assign(remaining.begin() + embedded_offset, remaining.end());
                            }
                        } else if (remaining.size() > 1000) {
                            auto name_it = std::search(remaining.begin(), remaining.end(), filename.begin(), filename.end());
                            if (name_it != remaining.end()) {
                                actual_content.assign(name_it + filename.size(), remaining.end());
                            } else {
                                actual_content = remaining;
                            }
                        }
                        if (!actual_content.empty()) {
                            std::lock_guard<std::mutex> lock(transfer_mutex);
                            file_transfers[full_path] = FileTransfer{actual_content, 0, actual_content.size()};
                        }
                    }
                    if (on_filebrowser_message) {
                        std::string msg = "Bigfile transfer started: " + filename;
                        pushEvent([this, msg]() { on_filebrowser_message(msg.c_str(), on_filebrowser_message_data); }, "filebrowser_message:PLO_RC_FILEBROWSER_DIR_largefile_start");
                    }
                    break;
                }
                if (!payload.empty() && payload[0] == grc::writeGByte(PLO_FILE)) {
                    processPacket(payload);
                    break;
                }
                size_t parse_offset = 0;
                int folder_len = grc::decodeGByte(payload[parse_offset++]);
                if (folder_len < 0 || parse_offset + static_cast<size_t>(folder_len) > payload.size()) break;
                std::string folder_path(payload.begin() + parse_offset, payload.begin() + parse_offset + folder_len);
                parse_offset += folder_len;

                std::vector<FileBrowserFileCacheEntry> files;
                while (parse_offset < payload.size()) {
                    if (parse_offset + 2 > payload.size()) break;
                    parse_offset += 2; // entry size, not needed after packet framing succeeded

                    if (parse_offset >= payload.size()) break;
                    int filename_len = grc::decodeGByte(payload[parse_offset++]);
                    if (filename_len < 0 || parse_offset + static_cast<size_t>(filename_len) > payload.size()) break;
                    std::string filename(payload.begin() + parse_offset, payload.begin() + parse_offset + filename_len);
                    parse_offset += filename_len;

                    if (parse_offset >= payload.size()) break;
                    int rights_len = grc::decodeGByte(payload[parse_offset++]);
                    if (rights_len < 0 || parse_offset + static_cast<size_t>(rights_len) > payload.size()) break;
                    std::string rights(payload.begin() + parse_offset, payload.begin() + parse_offset + rights_len);
                    parse_offset += rights_len;

                    if (parse_offset + 10 > payload.size()) break;
                    int size_value = decodeFileBrowserGInt5(payload, parse_offset);
                    parse_offset += 5;
                    int modified = decodeFileBrowserGInt5(payload, parse_offset);
                    parse_offset += 5;

                    FileBrowserFileCacheEntry entry;
                    entry.path = filename;
                    entry.rights = rights;
                    entry.size = size_value;
                    entry.modified = modified * 1000;
                    entry.is_directory = !filename.empty() && filename[filename.size() - 1] == '/';
                    files.push_back(entry);
                }

                int count = static_cast<int>(files.size());
                {
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    filebrowser_current_folder = folder_path;
                    filebrowser_files = files;
                }
                if (on_filebrowser_files) {
                    pushEvent([this, folder_path, count]() {
                        on_filebrowser_files(folder_path.c_str(), count, on_filebrowser_files_data);
                    }, "filebrowser_files:" + folder_path);
                }
                break;
            }
            case PLO_RC_FILEBROWSER_MESSAGE: { // 67 - FTP log message
                std::string ftp_message = grc::readCommaText(packet, offset);
                if (on_filebrowser_message) {
                    pushEvent([this, ftp_message]() {
                        on_filebrowser_message(ftp_message.c_str(), on_filebrowser_message_data);
                    });
                }
                break;
            }
            case PLO_LARGEFILESTART: { // 68 - Big file transfer start
                std::string basename(packet.begin() + offset, packet.end());
                std::string full_path;
                {
                    std::lock_guard<std::mutex> lock(transfer_mutex);
                    full_path = pending_file_download.empty() ? basename : pending_file_download;
                    FileTransfer transfer = {std::vector<uint8_t>(), 0, 0};
                    file_transfers[full_path] = transfer;
                }
                if (on_filebrowser_message) {
                    std::string msg = "Bigfile transfer started: " + basename;
                    pushEvent([this, msg]() { on_filebrowser_message(msg.c_str(), on_filebrowser_message_data); }, "filebrowser_message:largefile_start");
                }
                break;
            }
            case PLO_LARGEFILEEND: { // 69 - Big file transfer end
                std::string filename(packet.begin() + offset, packet.end());
                size_t newline_pos = filename.find('\n');
                if (newline_pos != std::string::npos) filename = filename.substr(0, newline_pos);

                // Find transfer and trigger callback
                std::string transfer_key;
                std::string content;
                {
                    std::lock_guard<std::mutex> lock(transfer_mutex);
                    if (!pending_file_download.empty() && file_transfers.count(pending_file_download)) {
                        transfer_key = pending_file_download;
                    } else if (file_transfers.count(filename)) {
                        transfer_key = filename;
                    }

                    if (!transfer_key.empty() && file_transfers[transfer_key].received > 0) {
                        auto& transfer = file_transfers[transfer_key];
                        content.assign(reinterpret_cast<const char*>(transfer.buffer.data()), transfer.buffer.size());
                        file_transfers.erase(transfer_key);
                    }
                    pending_file_download.clear();
                }

                if (!transfer_key.empty() && !content.empty()) {
                    if (on_filebrowser_message) {
                        std::string msg = "Bigfile transfer ended: " + filename;
                        pushEvent([this, msg]() { on_filebrowser_message(msg.c_str(), on_filebrowser_message_data); }, "filebrowser_message:largefile_end");
                    }
                    if (on_file_received) {
                        pushEvent([this, transfer_key, content]() {
                            on_file_received(transfer_key.c_str(), content.c_str(), content.length(), on_file_received_data);
                        }, "file_received:largefile_end:" + transfer_key);
                    }
                }
                break;
            }
            case PLO_PRIVATEMESSAGE: { // 37 - Private message
                if (offset + 2 <= packet.size()) {
                    int player_id = grc::decodeGShort(packet.data() + offset);
                    offset += 2;
                    std::string message(packet.begin() + offset, packet.end());
                    size_t comma_pos = message.find(',');
                    if (comma_pos != std::string::npos && comma_pos + 1 < message.length()) {
                        std::string msg_content = message.substr(comma_pos + 1);
                        if (!msg_content.empty() && msg_content.back() == ',') {
                            msg_content.pop_back();
                        }
                        std::string account;
                        std::string nick;
                        {
                            std::lock_guard<std::mutex> lock(cache_mutex);
                            for (const auto& player : player_cache) {
                                if (player.id == player_id) {
                                    if (player.account) account = player.account;
                                    if (player.nick) nick = player.nick;
                                    break;
                                }
                            }
                        }
                        if (on_private_message) {
                            pushEvent([this, player_id, account, nick, msg_content]() {
                                on_private_message(player_id, account.c_str(), nick.c_str(), msg_content.c_str(), on_private_message_data);
                            });
                        }
                    }
                }
                break;
            }
            case PLO_NEWWORLDTIME: { // 42 - World time update
                if (offset + 4 <= packet.size()) {
                    int b0 = (packet[offset] - 32) & 0xFF;
                    int b1 = (packet[offset+1] - 32) & 0xFF;
                    int b2 = (packet[offset+2] - 32) & 0xFF;
                    int b3 = (packet[offset+3] - 32) & 0xFF;
                    int world_time = (b0 << 21) | (b1 << 14) | (b2 << 7) | b3;
                    if (on_world_time) pushEvent([this, world_time]() { on_world_time(world_time, on_world_time_data); });
                }
                break;
            }
            case PLO_NC_CONTROL: { // 78 - NC control (rarely used)
                break;
            }
            case PLO_NC_LEVELLIST: {
                emitServerDataPacket("nc_levellist", offset);
                break;
            }
            case PLO_SERVERTEXT: { // 82 - Server text (PM server info, lister, etc)
                std::string message(packet.begin() + offset, packet.end());
                std::string untokenized = grc::gtokenizeReverseString(message);
                std::vector<std::string> parts;
                size_t start = 0;
                while (start < untokenized.length()) {
                    size_t end = untokenized.find('\n', start);
                    if (end == std::string::npos) {
                        parts.push_back(untokenized.substr(start));
                        break;
                    }
                    parts.push_back(untokenized.substr(start, end - start));
                    start = end + 1;
                }
                if (parts.size() >= 3 && parts[0] == protocolTextNamespace()) {
                    if (parts[1] == "pmservers") {
                        std::vector<std::string> names;
                        for (size_t i = 2; i < parts.size(); ++i) {
                            std::vector<std::string> entries = splitText(parts[i], ',');
                            for (const auto& entry : entries) {
                                std::string server_name = trimText(entry);
                                if (!server_name.empty() && server_name != "all") {
                                    names.push_back(server_name);
                                }
                            }
                        }
                        {
                            std::lock_guard<std::mutex> lock(cache_mutex);
                            pm_server_cache = names;
                            pm_server_ptr_cache.clear();
                            for (const auto& server_name : pm_server_cache) {
                                pm_server_ptr_cache.push_back(server_name.c_str());
                            }
                        }
                        if (on_pm_servers_updated) {
                            int count = static_cast<int>(names.size());
                            pushEvent([this, count]() {
                                if (on_pm_servers_updated) on_pm_servers_updated(count, on_pm_servers_updated_data);
                            });
                        }
                    } else if (parts[1] == "pmserverplayers") {
                        std::string server_name = parts[2];
                        std::string player_data;
                        for (size_t i = 3; i < parts.size(); ++i) {
                            if (i > 3) player_data += "\n";
                            player_data += parts[i];
                        }
                        if (on_pm_server_players) {
                            pushEvent([this, server_name, player_data]() {
                                on_pm_server_players(server_name.c_str(), player_data.c_str(), on_pm_server_players_data);
                            });
                        }
                    } else if (parts[1] == "irc" && parts.size() >= 3) {
                        std::string command = parts[2];
                        if (command == "join" && parts.size() >= 4) {
                            std::string channel = parts[3];
                            std::string line = "* Joined " + channel;
                            if (on_irc_message) pushEvent([this, channel, line]() {
                                on_irc_message(channel.c_str(), line.c_str(), on_irc_message_data);
                            });
                        } else if (command == "part" && parts.size() >= 4) {
                            std::string channel = parts[3];
                            std::string line = "* Left " + channel;
                            if (on_irc_message) pushEvent([this, channel, line]() {
                                on_irc_message(channel.c_str(), line.c_str(), on_irc_message_data);
                            });
                        } else if ((command == "privmsg" || command == "notice") && parts.size() >= 6) {
                            std::string source = parts[3], channel = parts[4], message = parts[5];
                            std::string line = (command == "notice") ? ("* " + source + ": " + message) : ("<" + source + "> " + message);
                            if (on_irc_message) pushEvent([this, channel, line]() {
                                on_irc_message(channel.c_str(), line.c_str(), on_irc_message_data);
                            });
                        }
                    } else if (parts[1] == "lister" && parts.size() >= 3 && parts[2] != "simpleserverlist") {
                        std::string command = parts[2];
                        if (command == "ban") {
                            std::string account = (parts.size() > 3) ? parts[3] : pending_ban_account;
                            std::string computer_id = (parts.size() > 4) ? parts[4] : "";
                            std::string details = (parts.size() > 5) ? joinText(parts, 5, "\n") : "";
                            if (account == protocolTextNamespace() && computer_id == "0" && !pending_ban_account.empty()) {
                                account = pending_ban_account;
                                computer_id.clear();
                            }
                            if (on_ban_data) {
                                pushEvent([this, account, computer_id, details]() {
                                    on_ban_data(account.c_str(), computer_id.c_str(), details.c_str(), on_ban_data_data);
                                });
                            }
                            pending_ban_account.clear();
                            pending_ban_player_id = -1;
                        } else if (command == "bantypes") {
                            std::string content = joinText(parts, 3, "\n");
                            if (on_ban_list_data) {
                                pushEvent([this, content]() {
                                    on_ban_list_data("bantypes", "", content.c_str(), on_ban_list_data_data);
                                });
                            }
                        } else if (command == "banhistory") {
                            std::string account = (parts.size() > 3) ? parts[3] : "";
                            std::string content = (parts.size() > 4) ? joinText(parts, 4, "\n") : "";
                            if (on_ban_list_data) {
                                pushEvent([this, account, content]() {
                                    on_ban_list_data("banhistory", account.c_str(), content.c_str(), on_ban_list_data_data);
                                });
                            }
                        } else if (command == "staffactivity") {
                            std::string account = (parts.size() > 3) ? parts[3] : "";
                            std::string content = (parts.size() > 4) ? joinText(parts, 4, "\n") : "";
                            if (on_ban_list_data) {
                                pushEvent([this, account, content]() {
                                    on_ban_list_data("staffactivity", account.c_str(), content.c_str(), on_ban_list_data_data);
                                });
                            }
                        }
                    } else if (parts[1] == "lister" && parts[2] == "simpleserverlist") {
                        std::string server_data_str;
                        for (size_t i = 3; i < parts.size(); ++i) {
                            if (i > 3) server_data_str += ",";
                            server_data_str += parts[i];
                        }
                        server_cache.clear();
                        size_t i = 0;
                        size_t pos = 0;
                        std::vector<std::string> entries;
                        bool in_quotes = false;
                        std::string current;
                        for (char c : server_data_str) {
                            if (c == '"') {
                                in_quotes = !in_quotes;
                            } else if (c == ',' && !in_quotes) {
                                entries.push_back(current);
                                current.clear();
                            } else {
                                current += c;
                            }
                        }
                        if (!current.empty()) entries.push_back(current);

                        for (size_t idx = 0; idx + 2 < entries.size(); idx += 3) {
                            std::string server_name = entries[idx];
                            std::string display_name = entries[idx + 1];
                            int player_count = 0;
                            try {
                                player_count = std::stoi(entries[idx + 2]);
                            } catch(...) {
                                continue;
                            }
                            if (server_name.front() == '"') server_name = server_name.substr(1);
                            if (server_name.back() == '"') server_name.pop_back();
                            if (display_name.front() == '"') display_name = display_name.substr(1);
                            if (display_name.back() == '"') display_name.pop_back();

                            if (!server_name.empty() && !display_name.empty()) {
                                RCServer server;
                                server.name = grcStrdup(display_name.c_str());
                                server.players = player_count;
                                server_cache.push_back(server);
                            }
                        }
                    }
                }
                break;
            }
            case PLO_LARGEFILESIZE: { // 84 - Big file size
                if (offset + 5 <= packet.size()) {
                    int b0 = grc::decodeGByte(packet[offset++]);
                    int b1 = grc::decodeGByte(packet[offset++]);
                    int b2 = grc::decodeGByte(packet[offset++]);
                    int b3 = grc::decodeGByte(packet[offset++]);
                    int b4 = grc::decodeGByte(packet[offset++]);
                    size_t file_size = ((size_t)b0 << 28) | ((size_t)b1 << 21) | ((size_t)b2 << 14) | ((size_t)b3 << 7) | b4;

                    // Find the first transfer with size = 0 and set its size
                    {
                        std::lock_guard<std::mutex> lock(transfer_mutex);
                        for (auto& pair : file_transfers) {
                            if (pair.second.size == 0) {
                                pair.second.size = file_size;
                                break;
                            }
                        }
                    }
                }
                break;
            }
            case PLO_RC_MAXUPLOADFILESIZE: { // 103 - Server upload limit
                if (offset + 5 <= packet.size()) {
                    long long b0 = grc::decodeGByte(packet[offset++]);
                    long long b1 = grc::decodeGByte(packet[offset++]);
                    long long b2 = grc::decodeGByte(packet[offset++]);
                    long long b3 = grc::decodeGByte(packet[offset++]);
                    long long b4 = grc::decodeGByte(packet[offset++]);
                    max_upload_file_size = (b0 << 28) | (b1 << 21) | (b2 << 14) | (b3 << 7) | b4;
                    if (on_max_upload_file_size) {
                        long long value = max_upload_file_size;
                        pushEvent([this, value]() { on_max_upload_file_size(value, on_max_upload_file_size_data); });
                    }
                }
                break;
            }
            case PLO_BOARDPACKET: {
                emitServerDataPacket("boardpacket", offset);
                break;
            }
            case PLO_STATUSLIST: {
                emitServerDataPacket("statuslist", offset);
                break;
            }
            case PLO_CLEARWEAPONS: {
                for (auto& weapon : weapon_cache) {
                    if (weapon.name) free(weapon.name);
                    if (weapon.image) free(weapon.image);
                }
                weapon_cache.clear();
                emitServerDataPacket("clearweapons", offset);
                break;
            }
            case PLO_FILE: { // 102 - File data (single-packet or chunk)
                if (offset + 5 <= packet.size()) {
                    // Parse modified date (5 bytes)
                    int b0 = grc::decodeGByte(packet[offset++]);
                    int b1 = grc::decodeGByte(packet[offset++]);
                    int b2 = grc::decodeGByte(packet[offset++]);
                    int b3 = grc::decodeGByte(packet[offset++]);
                    int b4 = grc::decodeGByte(packet[offset++]);
                    size_t modified_date = ((size_t)b0 << 28) | ((size_t)b1 << 21) | ((size_t)b2 << 14) | ((size_t)b3 << 7) | b4;

                    if (offset < packet.size()) {
                        int filename_len = grc::decodeGByte(packet[offset++]);
                        if (offset + filename_len <= packet.size()) {
                            std::string filename(packet.begin() + offset, packet.begin() + offset + filename_len);
                            offset += filename_len;
                            std::vector<uint8_t> content(packet.begin() + offset, packet.end());

                            // Check if this is part of a big file transfer
                            std::string transfer_key;
                            std::string chunk_msg;
                            size_t chunk_received = 0;
                            size_t chunk_total = 0;
                            {
                                std::lock_guard<std::mutex> lock(transfer_mutex);
                                if (file_transfers.count(filename)) transfer_key = filename;
                                else if (!pending_file_download.empty() && file_transfers.count(pending_file_download)) transfer_key = pending_file_download;
                                if (!transfer_key.empty()) {
                                    auto& transfer = file_transfers[transfer_key];
                                    transfer.buffer.insert(transfer.buffer.end(), content.begin(), content.end());
                                    transfer.received += content.size();
                                    chunk_msg = "Received chunk: " + std::to_string(transfer.received) + "/" + std::to_string(transfer.size) + " bytes for " + filename;
                                    chunk_received = transfer.received;
                                    chunk_total = transfer.size;
                                }
                            }
                            if (!transfer_key.empty()) {
                                if (on_filebrowser_message) {
                                    std::string msg = chunk_msg;
                                    pushEvent([this, msg]() { on_filebrowser_message(msg.c_str(), on_filebrowser_message_data); }, "filebrowser_message:file_chunk");
                                }
                                completeTransferIfReady(transfer_key, chunk_received, chunk_total, "file_chunk_size_complete");
                            } else {
                                // Single-packet file download
                                if (on_file_received) {
                                    std::string content_str((char*)content.data(), content.size());
                                    pushEvent([this, filename, content_str]() {
                                        on_file_received(filename.c_str(), content_str.c_str(), content_str.length(), on_file_received_data);
                                    }, "file_received:single_packet:" + filename);
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
    }
    bool hasActiveLargeFileTransfer() {
        std::lock_guard<std::mutex> lock(transfer_mutex);
        for (const auto& pair : file_transfers) {
            if (pair.second.size > 0) return true;
        }
        return false;
    }
    bool isLargeFileEndFrame(const std::vector<uint8_t>& data) {
        if (data.size() < 2 || grc::decodeGByte(data[0]) != PLO_LARGEFILEEND) return false;
        size_t term_pos = 1;
        while (term_pos < data.size() && data[term_pos] != 0x0A) term_pos++;
        if (term_pos >= data.size()) return false;
        if (term_pos + 1 != data.size()) return false;
        std::string filename(data.begin() + 1, data.begin() + term_pos);
        size_t newline_pos = filename.find('\n');
        if (newline_pos != std::string::npos) filename = filename.substr(0, newline_pos);
        std::lock_guard<std::mutex> lock(transfer_mutex);
        if (!pending_file_download.empty()) {
            if (filename == pending_file_download) return true;
            size_t slash = pending_file_download.find_last_of("/\\");
            std::string basename = slash == std::string::npos ? pending_file_download : pending_file_download.substr(slash + 1);
            if (filename == basename) return true;
        }
        return file_transfers.count(filename) > 0;
    }
    bool looksLikeFramedPacketData(const std::vector<uint8_t>& data) {
        if (data.empty()) return false;
        size_t offset = 0;
        bool saw_packet = false;
        while (offset < data.size()) {
            if (data[offset] == 132) {
                if (offset + 5 > data.size()) return false;
                int raw_length = ((data[offset + 1] - 32) << 14) + ((data[offset + 2] - 32) << 7) + (data[offset + 3] - 32);
                if (raw_length < 0 || offset + 5 + static_cast<size_t>(raw_length) > data.size()) return false;
                saw_packet = true;
                offset += 5 + static_cast<size_t>(raw_length);
                continue;
            }
            size_t term_pos = offset;
            while (term_pos < data.size() && data[term_pos] != 0x0A) term_pos++;
            if (term_pos >= data.size()) return false;
            if (term_pos == offset) return false;
            if (data[offset] < 32) return false;
            saw_packet = true;
            offset = term_pos + 1;
        }
        return saw_packet;
    }
    bool appendActiveLargeFileChunk(const std::vector<uint8_t>& data) {
        if (data.empty()) return false;
        std::string transfer_key;
        size_t received = 0;
        size_t total = 0;
        {
            std::lock_guard<std::mutex> lock(transfer_mutex);
            if (!pending_file_download.empty()) {
                auto it = file_transfers.find(pending_file_download);
                if (it != file_transfers.end() && it->second.size > 0) {
                    transfer_key = pending_file_download;
                }
            }
            if (transfer_key.empty()) {
                for (const auto& pair : file_transfers) {
                    if (pair.second.size > 0) {
                        transfer_key = pair.first;
                        break;
                    }
                }
            }
            if (transfer_key.empty()) return false;

            auto& transfer = file_transfers[transfer_key];
            transfer.buffer.insert(transfer.buffer.end(), data.begin(), data.end());
            transfer.received += data.size();
            received = transfer.received;
            total = transfer.size;
        }
        if (on_filebrowser_message) {
            std::string msg = "Received chunk: " + std::to_string(received) + "/" + std::to_string(total) + " bytes for " + transfer_key;
            pushEvent([this, msg]() { on_filebrowser_message(msg.c_str(), on_filebrowser_message_data); }, "filebrowser_message:largefile_raw_chunk");
        }
        completeTransferIfReady(transfer_key, received, total, "largefile_size_complete");
        return true;
    }
    std::string pendingDownloadPath() {
        std::lock_guard<std::mutex> lock(transfer_mutex);
        return pending_file_download;
    }
    size_t expectedDownloadSize(const std::string& path) {
        if (path.empty()) return 0;
        size_t slash = path.find_last_of("/\\");
        std::string basename = slash == std::string::npos ? path : path.substr(slash + 1);
        std::lock_guard<std::mutex> lock(cache_mutex);
        for (const auto& entry : filebrowser_files) {
            if (entry.is_directory) continue;
            if (entry.path == path || entry.path == basename) return entry.size > 0 ? static_cast<size_t>(entry.size) : 0;
            if (!filebrowser_current_folder.empty()) {
                std::string full = filebrowser_current_folder + entry.path;
                if (full == path) return entry.size > 0 ? static_cast<size_t>(entry.size) : 0;
            }
        }
        return 0;
    }
    bool emitPendingFilePayload(const std::string& path, const std::vector<uint8_t>& content, const char* trace_label) {
        if (path.empty() || content.empty()) return false;
        {
            std::lock_guard<std::mutex> lock(transfer_mutex);
            file_transfers.erase(path);
            if (pending_file_download == path) pending_file_download.clear();
        }
        if (on_filebrowser_message) {
            std::string msg = std::string("File downloaded: ") + path;
            pushEvent([this, msg]() { on_filebrowser_message(msg.c_str(), on_filebrowser_message_data); }, "filebrowser_message:pending_payload_done");
        }
        if (on_file_received) {
            std::string content_str(reinterpret_cast<const char*>(content.data()), content.size());
            pushEvent([this, path, content_str]() {
                on_file_received(path.c_str(), content_str.c_str(), content_str.length(), on_file_received_data);
            }, std::string("file_received:") + trace_label + ":" + path);
        }
        return true;
    }
    bool completeTransferIfReady(const std::string& path, size_t received, size_t total, const char* trace_label) {
        if (path.empty() || total == 0 || received < total) return false;
        std::vector<uint8_t> content;
        {
            std::lock_guard<std::mutex> lock(transfer_mutex);
            auto it = file_transfers.find(path);
            if (it == file_transfers.end() || it->second.received < it->second.size) return false;
            content = it->second.buffer;
        }
        return emitPendingFilePayload(path, content, trace_label);
    }
    bool handlePendingUnframedFilePayload(const std::vector<uint8_t>& data) {
        if (data.empty()) return false;
        std::string path = pendingDownloadPath();
        if (path.empty()) return false;

        std::vector<uint8_t> content;
        if (grc::decodeGByte(data[0]) == PLO_LARGEFILESTART) {
            size_t slash = path.find_last_of("/\\");
            std::string basename = slash == std::string::npos ? path : path.substr(slash + 1);
            size_t content_start = std::string::npos;
            if (!basename.empty() && data.size() > 1 + basename.size() &&
                std::equal(basename.begin(), basename.end(), data.begin() + 1)) {
                content_start = 1 + basename.size();
                if (content_start < data.size() && (data[content_start] == 0 || data[content_start] == '\n' || data[content_start] == '\r')) {
                    ++content_start;
                }
            } else {
                for (size_t i = 1; i < data.size(); ++i) {
                    if (data[i] == 0 || data[i] == '\n' || data[i] == '\r') {
                        content_start = i + 1;
                        break;
                    }
                }
            }
            if (content_start == std::string::npos || content_start >= data.size()) return false;
            content.assign(data.begin() + content_start, data.end());
        } else {
            content = data;
        }

        size_t expected_size = expectedDownloadSize(path);
        if (expected_size == 0 || content.size() >= expected_size) {
            return emitPendingFilePayload(path, content, "pending_unframed");
        }

        {
            std::lock_guard<std::mutex> lock(transfer_mutex);
            FileTransfer transfer = {content, expected_size, content.size()};
            file_transfers[path] = transfer;
        }
        if (on_filebrowser_message) {
            std::string msg = "Received chunk: " + std::to_string(content.size()) + "/" + std::to_string(expected_size) + " bytes for " + path;
            pushEvent([this, msg]() { on_filebrowser_message(msg.c_str(), on_filebrowser_message_data); }, "filebrowser_message:pending_unframed_chunk");
        }
        return true;
    }
    void clearWeaponCache() {
        std::lock_guard<std::mutex> lock(cache_mutex);
        for (auto& weapon : weapon_cache) {
            if (weapon.name) free(weapon.name);
            if (weapon.image) free(weapon.image);
            if (weapon.script) free(weapon.script);
        }
        weapon_cache.clear();
    }
    void clearClassCache() {
        std::lock_guard<std::mutex> lock(cache_mutex);
        for (auto& cls : class_cache) {
            if (cls.name) free(cls.name);
            if (cls.script) free(cls.script);
        }
        class_cache.clear();
    }
    void clearNPCCache() {
        std::lock_guard<std::mutex> lock(cache_mutex);
        for (auto& npc : npc_cache) {
            if (npc.name) free(npc.name);
            if (npc.type) free(npc.type);
            if (npc.image) free(npc.image);
            if (npc.script) free(npc.script);
        }
        npc_cache.clear();
    }
    void processNCPacket(const std::vector<uint8_t>& packet) {
        if (packet.empty()) return;
        uint8_t packet_id = grc::decodeGByte(packet[0]);
        size_t offset = 1;

        // Handle NC disconnect message
        if (packet_id == 16) {
            std::string disconnect_msg(packet.begin() + offset, packet.end());
            if (on_server_data) {
                std::string msg = "[NC] DISCONNECT: " + disconnect_msg;
                pushEvent([this, msg]() { on_server_data("nc_message", msg.c_str(), on_server_data_data); });
            }
            return;
        }

        if (!nc_authenticated && packet_id != 16) {
            nc_authenticated = true;
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            std::vector<uint8_t> weapon_request = nc_protocol.sendPacket(PLI_NC_WEAPONLISTGET, std::vector<uint8_t>());
            grc::sendAll(nc_socket, weapon_request.data(), weapon_request.size());
        }

        if (packet_id == PLO_RC_CHAT) {
            std::string message(packet.begin() + offset, packet.end());
            size_t pos = 0;
            while ((pos = message.find(" of +", pos)) != std::string::npos) {
                message.replace(pos, 5, " of ");
                pos += 4;
            }
            if (on_server_data) {
                pushEvent([this, message]() {
                    on_server_data("nc_message", message.c_str(), on_server_data_data);
                });
            }
            return;
        }

        // NC server INCOMING packets (PLO_NC_)
        switch (packet_id) {
            case PLO_NC_WEAPONLISTGET: { // 167 - Weapon list
                clearWeaponCache();
                int weapon_count = 0;
                while (offset < packet.size()) {
                    if (offset >= packet.size()) break;
                    int name_len = grc::decodeGByte(packet[offset++]);
                    if (offset + name_len > packet.size()) break;
                    std::string weapon_name(packet.begin() + offset, packet.begin() + offset + name_len);
                    offset += name_len;
                    RCWeapon weapon;
                    weapon.name = grcStrdup(weapon_name.c_str());
                    weapon.image = grcStrdup("");
                    weapon.script = grcStrdup("");
                    {
                        std::lock_guard<std::mutex> lock(cache_mutex);
                        weapon_cache.push_back(weapon);
                    }
                    weapon_count++;
                }
                break;
            }
            case PLO_NC_CLASSADD: { // 163 - Class added
                if (offset < packet.size()) {
                    std::string class_name(packet.begin() + offset, packet.end());
                    size_t newline_pos = class_name.find('\n');
                    if (newline_pos != std::string::npos) class_name = class_name.substr(0, newline_pos);
                    if (!class_name.empty()) {
                        bool exists = false;
                        {
                            std::lock_guard<std::mutex> lock(cache_mutex);
                            for (const auto& c : class_cache) {
                                if (strcmp(c.name, class_name.c_str()) == 0) {
                                    exists = true;
                                    break;
                                }
                            }
                            if (!exists) {
                                RCClass cls;
                                cls.name = grcStrdup(class_name.c_str());
                                cls.script = grcStrdup("");
                                class_cache.push_back(cls);
                            }
                        }
                        if (!exists && on_class_added) {
                            pushEvent([this, class_name]() {
                                on_class_added(class_name.c_str(), on_class_added_data);
                            });
                        }
                    }
                }
                break;
            }
            case PLO_NC_LEVELDUMP: { // 164 - Local NPC/level variable dump
                std::string text;
                if (offset < packet.size()) {
                    std::string tokenized(packet.begin() + offset, packet.end());
                    text = grc::gtokenizeReverseString(tokenized);
                }
                std::string level;
                {
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    level = pending_local_npcs_level;
                    pending_local_npcs_level.clear();
                }
                if (on_local_npcs) {
                    pushEvent([this, level, text]() {
                        if (on_local_npcs) on_local_npcs(level.c_str(), text.c_str(), on_local_npcs_data);
                    });
                }
                break;
            }
            case PLO_NC_CLASSDELETE: { // 188 - Class deleted
                if (offset < packet.size()) {
                    std::string class_name(packet.begin() + offset, packet.end());
                    size_t newline_pos = class_name.find('\n');
                    if (newline_pos != std::string::npos) class_name = class_name.substr(0, newline_pos);
                    bool deleted = false;
                    {
                        std::lock_guard<std::mutex> lock(cache_mutex);
                        for (auto it = class_cache.begin(); it != class_cache.end(); ) {
                            if (strcmp(it->name, class_name.c_str()) == 0) {
                                free(it->name);
                                free(it->script);
                                it = class_cache.erase(it);
                                deleted = true;
                                break;
                            } else {
                                ++it;
                            }
                        }
                    }
                    if (deleted && on_class_deleted) pushEvent([this, class_name]() { on_class_deleted(class_name.c_str(), on_class_deleted_data); });
                }
                break;
            }
            case PLO_NC_WEAPONGET: { // 192 - Weapon script response
                if (offset < packet.size()) {
                    int name_len = grc::decodeGByte(packet[offset++]);
                    if (offset + name_len > packet.size()) break;
                    std::string weapon_name(packet.begin() + offset, packet.begin() + offset + name_len);
                    offset += name_len;
                    if (offset >= packet.size()) break;
                    int image_len = grc::decodeGByte(packet[offset++]);
                    if (offset + image_len > packet.size()) break;
                    offset += image_len;
                    std::vector<uint8_t> encoded_script(packet.begin() + offset, packet.end());
                    std::string script;
                    for (uint8_t b : encoded_script) {
                        if (b == 0xa7) script += '\n';
                        else script += (char)b;
                    }
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    for (auto& weapon : weapon_cache) {
                        if (strcmp(weapon.name, weapon_name.c_str()) == 0) {
                            if (weapon.script) free(weapon.script);
                            weapon.script = grcStrdup(script.c_str());
                            break;
                        }
                    }
                    if (on_script_received) {
                        pushEvent([this, weapon_name, script]() {
                            on_script_received("weapon", weapon_name.c_str(), 0, script.c_str(), on_script_received_data);
                        });
                    }
                }
                break;
            }
            case PLO_NC_NPCATTRIBUTES: { // 157 - NPC attributes/properties
                if (offset < packet.size()) {
                    std::string comma_text(packet.begin() + offset, packet.end());
                    std::string untokenized = grc::gtokenizeReverseString(comma_text);
                    int npc_id = pending_npc_attributes_id;
                    pending_npc_attributes_id = -1;
                    if (on_npc_attributes) {
                        pushEvent([this, npc_id, untokenized]() {
                            on_npc_attributes(npc_id, untokenized.c_str(), on_npc_attributes_data);
                        });
                    }
                }
                break;
            }
            case PLO_NC_NPCADD: { // 158 - NPC added (uses GInt3 for ID!)
                if (offset + 3 <= packet.size()) {
                    int npc_id = grc::decodeGInt3(packet.data() + offset);
                    offset += 3;
                    std::string name, type, level;
                    // Parse props: 50 = name, 51 = type, 52 = level
                    while (offset < packet.size()) {
                        int prop_id = grc::decodeGByte(packet[offset++]);
                        if (prop_id == 50 && offset < packet.size()) {
                            int name_len = grc::decodeGByte(packet[offset++]);
                            if (offset + name_len <= packet.size()) {
                                name = std::string(packet.begin() + offset, packet.begin() + offset + name_len);
                                offset += name_len;
                            }
                        } else if (prop_id == 51 && offset < packet.size()) {
                            int type_len = grc::decodeGByte(packet[offset++]);
                            if (offset + type_len <= packet.size()) {
                                type = std::string(packet.begin() + offset, packet.begin() + offset + type_len);
                                offset += type_len;
                            }
                        } else if (prop_id == 52 && offset < packet.size()) {
                            int level_len = grc::decodeGByte(packet[offset++]);
                            if (offset + level_len <= packet.size()) {
                                level = std::string(packet.begin() + offset, packet.begin() + offset + level_len);
                                offset += level_len;
                            }
                        } else {
                            break;
                        }
                    }
                    RCNPC npc;
                    npc.id = npc_id;
                    npc.name = grcStrdup(name.c_str());
                    npc.type = grcStrdup(type.c_str());
                    npc.image = grcStrdup("");
                    npc.script = grcStrdup("");
                    {
                        std::lock_guard<std::mutex> lock(cache_mutex);
                        npc_cache.push_back(npc);
                    }
                    if (on_npc_added) {
                        pushEvent([this, npc_id, name]() {
                            on_npc_added(npc_id, name.c_str(), on_npc_added_data);
                        });
                    }
                }
                break;
            }
            case PLO_NC_NPCDELETE: { // 159 - NPC deleted (uses GInt3 for ID!)
                if (offset + 3 <= packet.size()) {
                    int npc_id = grc::decodeGInt3(packet.data() + offset);
                    offset += 3;
                    {
                        std::lock_guard<std::mutex> lock(cache_mutex);
                        for (auto it = npc_cache.begin(); it != npc_cache.end(); ) {
                            if (it->id == npc_id) {
                                free(it->name);
                                free(it->type);
                                free(it->image);
                                free(it->script);
                                it = npc_cache.erase(it);
                                break;
                            } else {
                                ++it;
                            }
                        }
                    }
                    if (on_npc_deleted) pushEvent([this, npc_id]() { on_npc_deleted(npc_id, on_npc_deleted_data); });
                }
                break;
            }
            case PLO_NC_NPCSCRIPT: { // 160 - NPC script response (uses GInt3 for ID!)
                if (offset + 3 <= packet.size()) {
                    int npc_id = grc::decodeGInt3(packet.data() + offset);
                    offset += 3;
                    std::string npc_name;
                    std::string script;
                    if (offset < packet.size()) {
                        std::string tokenized(packet.begin() + offset, packet.end());
                        script = grc::gtokenizeReverseString(tokenized);
                    }
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    for (auto& npc : npc_cache) {
                        if (npc.id == npc_id) {
                            if (npc.name) npc_name = npc.name;
                            if (npc.script) free(npc.script);
                            npc.script = grcStrdup(script.c_str());
                            break;
                        }
                    }
                    if (on_script_received) {
                        pushEvent([this, npc_name, npc_id, script]() {
                            on_script_received("npc", npc_name.c_str(), npc_id, script.c_str(), on_script_received_data);
                        });
                    }
                }
                break;
            }
            case PLO_NC_NPCFLAGS: { // 161 - NPC flags response (uses GInt3 for ID!)
                if (offset + 3 <= packet.size()) {
                    int npc_id = grc::decodeGInt3(packet.data() + offset);
                    offset += 3;
                    std::string flags;
                    if (offset < packet.size()) {
                        std::string tokenized(packet.begin() + offset, packet.end());
                        flags = grc::gtokenizeReverseString(tokenized);
                    }
                    {
                        std::lock_guard<std::mutex> lock(cache_mutex);
                        npc_flags_cache[npc_id] = flags;
                    }
                    if (on_npc_flags) {
                        pushEvent([this, npc_id, flags]() {
                            if (on_npc_flags) on_npc_flags(npc_id, flags.c_str(), on_npc_flags_data);
                        });
                    }
                }
                break;
            }
            case PLO_NC_CLASSGET: { // 162 - Class script response
                if (offset < packet.size()) {
                    int name_len = grc::decodeGByte(packet[offset++]);
                    if (offset + name_len <= packet.size()) {
                        std::string class_name(packet.begin() + offset, packet.begin() + offset + name_len);
                        offset += name_len;
                        std::string script;
                        if (offset < packet.size()) {
                            std::string tokenized(packet.begin() + offset, packet.end());
                            script = grc::gtokenizeReverseString(tokenized);
                        }
                        std::lock_guard<std::mutex> lock(cache_mutex);
                        for (auto& cls : class_cache) {
                            if (strcmp(cls.name, class_name.c_str()) == 0) {
                                if (cls.script) free(cls.script);
                                cls.script = grcStrdup(script.c_str());
                                break;
                            }
                        }
                        if (on_script_received) {
                            pushEvent([this, class_name, script]() {
                                on_script_received("class", class_name.c_str(), 0, script.c_str(), on_script_received_data);
                            });
                        }
                    }
                }
                break;
            }
        }
    }
    void recvLoop() {
        std::vector<uint8_t> buffer;
        while (running && game_socket != INVALID_SOCKET) {
            uint8_t length_bytes[2];
            if (!grc::recvAll(game_socket, length_bytes, 2)) {
                setError("Failed to recv packet length");
                break;
            }
            uint16_t packet_length = (length_bytes[0] << 8) | length_bytes[1];
            if (packet_length == 0 || packet_length > 65535) {
                setError("Invalid packet length");
                break;
            }
            std::vector<uint8_t> packet_data(packet_length);
            if (!grc::recvAll(game_socket, packet_data.data(), packet_length)) {
                setError("Failed to recv packet data");
                break;
            }
            std::vector<uint8_t> decrypted = protocol.decryptPacket(packet_data.data(), packet_data.size());
            if (!validateHeap("before framing loop")) {
                break;
            }
            if (decrypted.size() > 2 && decrypted[0] == 'B' && decrypted[1] == 'Z') {
                std::vector<uint8_t> bz_decompressed = grc::bzip2Decompress(decrypted.data(), decrypted.size());
                if (!bz_decompressed.empty()) decrypted = bz_decompressed;
            }
            size_t offset = 0;
            while (offset < decrypted.size()) {
                if (offset >= decrypted.capacity()) {
                    break;
                }
                if (decrypted[offset] == 132) {
                    if (offset + 5 <= decrypted.size()) {
                        int raw_length = ((decrypted[offset + 1] - 32) << 14) + ((decrypted[offset + 2] - 32) << 7) + (decrypted[offset + 3] - 32);
                        if (offset + 5 + raw_length <= decrypted.size()) {
                            std::vector<uint8_t> raw_packet(decrypted.begin() + offset + 5, decrypted.begin() + offset + 5 + raw_length);
                            if (!raw_packet.empty() && raw_packet.back() == 0x0A) raw_packet.pop_back();
                            if (!raw_packet.empty() && raw_packet[0] >= 32) processPacket(raw_packet);
                            offset += 5 + raw_length;
                            continue;
                        }
                    }
                    break;
                }
                size_t term_pos = offset;
                while (term_pos < decrypted.size() && decrypted[term_pos] != 0x0A) term_pos++;
                if (term_pos >= decrypted.size()) break;
                {
                    std::vector<uint8_t> single_packet(decrypted.begin() + offset, decrypted.begin() + term_pos);
                    processPacket(single_packet);
                }
                offset = term_pos + 1;
            }
        }
        connected = false;
        if (on_disconnected) pushEvent([this]() { on_disconnected("Connection closed", on_disconnected_data); });
    }
    void ncRecvLoop() {
        while (running && nc_socket != INVALID_SOCKET) {
            uint8_t length_bytes[2];
            if (!grc::recvAll(nc_socket, length_bytes, 2)) {
                break;
            }
            uint16_t packet_length = (length_bytes[0] << 8) | length_bytes[1];
            if (packet_length == 0 || packet_length > 65535) {
                break;
            }
            std::vector<uint8_t> packet_data(packet_length);
            if (!grc::recvAll(nc_socket, packet_data.data(), packet_length)) {
                break;
            }
            std::vector<uint8_t> decompressed = nc_protocol.decryptPacket(packet_data.data(), packet_data.size());
            size_t offset = 0;
            while (offset < decompressed.size()) {
                size_t term_pos = offset;
                while (term_pos < decompressed.size() && decompressed[term_pos] != 0x0A) term_pos++;
                if (term_pos >= decompressed.size()) break;
                std::vector<uint8_t> single_packet(decompressed.begin() + offset, decompressed.begin() + term_pos);
                processNCPacket(single_packet);
                offset = term_pos + 1;
            }
        }
        nc_connected = false;
    }
};
RCHandle rc_connect(const char* listserver_host, int listserver_port, const char* account, const char* password) {
    if (!listserver_host || !account || !password) return nullptr;
#ifdef _WIN32
    static bool wsa_initialized = false;
    if (!wsa_initialized) {
        WSADATA wsa_data;
        WSAStartup(MAKEWORD(2, 2), &wsa_data);
        wsa_initialized = true;
    }
#endif
    RCConnection* conn = new RCConnection();
    conn->listserver_host = listserver_host;
    conn->listserver_port = listserver_port;
    conn->account = account;
    conn->password = password;
    conn->is_new_protocol = true;
    std::string error;
    conn->servers = grc::fetchServerList(listserver_host, listserver_port, account, password, error);
    if (conn->servers.empty()) {
        conn->setError(error);
        return conn;
    }
    return conn;
}
int rc_get_servers(RCHandle handle, RCServer** servers_out) {
    if (!handle || !servers_out) return 0;
    RCConnection* conn = (RCConnection*)handle;
    conn->server_cache.clear();
    for (const auto& server : conn->servers) {
        RCServer rc_server;
        rc_server.name = grcStrdup(server.name.c_str());
        rc_server.ip = grcStrdup(server.ip.c_str());
        rc_server.port = server.port;
        rc_server.players = server.players;
        rc_server.language = grcStrdup(server.language.c_str());
        rc_server.description = grcStrdup(server.description.c_str());
        conn->server_cache.push_back(rc_server);
    }
    *servers_out = conn->server_cache.data();
    return conn->server_cache.size();
}
int rc_connect_to_server(RCHandle handle, int server_index) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (server_index < 0 || server_index >= conn->servers.size()) {
        conn->setError("Invalid server index");
        return 0;
    }
    conn->running = false;
    conn->authenticated = false;
    conn->connected = false;
    conn->nc_authenticated = false;
    conn->nc_connected = false;
    if (conn->game_socket != INVALID_SOCKET) {
        closesocket(conn->game_socket);
        conn->game_socket = INVALID_SOCKET;
    }
    if (conn->nc_socket != INVALID_SOCKET) {
        closesocket(conn->nc_socket);
        conn->nc_socket = INVALID_SOCKET;
    }
    if (conn->recv_thread.joinable()) conn->recv_thread.join();
    if (conn->nc_recv_thread.joinable()) conn->nc_recv_thread.join();
    const auto& server = conn->servers[server_index];
    conn->game_host = server.ip;
    conn->game_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->game_socket == INVALID_SOCKET) {
        conn->setError("Failed to create socket");
        return 0;
    }
    struct hostent* he = gethostbyname(server.ip.c_str());
    if (!he) {
        conn->setError("Failed to resolve server host");
        closesocket(conn->game_socket);
        conn->game_socket = INVALID_SOCKET;
        return 0;
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server.port);
    server_addr.sin_addr = *((struct in_addr*)he->h_addr);
    if (connect(conn->game_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        conn->setError("Failed to connect to server");
        closesocket(conn->game_socket);
        conn->game_socket = INVALID_SOCKET;
        return 0;
    }
    std::string login_payload = "vGSERV025";
    login_payload += grc::get1PlusTextNetString(conn->account);
    login_payload += grc::get1PlusTextNetString(conn->password);
    login_payload += grc::generatePcidList();
    std::vector<uint8_t> login_data(login_payload.begin(), login_payload.end());
    std::vector<uint8_t> login_packet = conn->protocol.sendPacket(PLI_TOALL, login_data);
    conn->protocol.setEncryptionKey(0x56);
    if (!grc::sendAll(conn->game_socket, login_packet.data(), login_packet.size())) {
        conn->setError("Failed to send login");
        closesocket(conn->game_socket);
        conn->game_socket = INVALID_SOCKET;
        return 0;
    }
    conn->connected = true;
    conn->running = true;
    conn->recv_thread = std::thread(&RCConnection::recvLoop, conn);
    return 1;
}
int rc_is_connected(RCHandle handle) {
    if (!handle) return 0;
    return ((RCConnection*)handle)->connected ? 1 : 0;
}
int rc_is_authenticated(RCHandle handle) {
    if (!handle) return 0;
    return ((RCConnection*)handle)->authenticated ? 1 : 0;
}
int rc_is_nc_connected(RCHandle handle) {
    if (!handle) return 0;
    return ((RCConnection*)handle)->nc_connected ? 1 : 0;
}
int rc_is_nc_authenticated(RCHandle handle) {
    if (!handle) return 0;
    return ((RCConnection*)handle)->nc_authenticated ? 1 : 0;
}
int rc_connect_to_nc_server(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (conn->nc_connected && conn->nc_socket != INVALID_SOCKET) return 1;
    conn->nc_authenticated = false;
    conn->nc_connected = false;
    if (conn->nc_socket != INVALID_SOCKET) {
        closesocket(conn->nc_socket);
        conn->nc_socket = INVALID_SOCKET;
    }
    if (conn->nc_recv_thread.joinable()) conn->nc_recv_thread.join();
    if (conn->npc_server_address.empty()) {
        conn->setError("NC server address not received");
        return 0;
    }
    size_t comma_pos = conn->npc_server_address.find(',');
    if (comma_pos == std::string::npos) {
        conn->setError("Invalid NC server address format");
        return 0;
    }
    std::string nc_host = conn->npc_server_address.substr(0, comma_pos);
    int nc_port = std::atoi(conn->npc_server_address.substr(comma_pos + 1).c_str());
    if ((nc_host == "127.0.0.1" || nc_host == "localhost" || nc_host == "0.0.0.0") && !conn->game_host.empty()) {
        nc_host = conn->game_host;
    }
    conn->nc_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->nc_socket == INVALID_SOCKET) {
        conn->setError("Failed to create NC socket");
        return 0;
    }
    struct hostent* he = gethostbyname(nc_host.c_str());
    if (!he) {
        conn->setError("Failed to resolve NC server host");
        closesocket(conn->nc_socket);
        conn->nc_socket = INVALID_SOCKET;
        return 0;
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(nc_port);
    server_addr.sin_addr = *((struct in_addr*)he->h_addr);
    if (connect(conn->nc_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        conn->setError("Failed to connect to NC server");
        closesocket(conn->nc_socket);
        conn->nc_socket = INVALID_SOCKET;
        return 0;
    }
    std::vector<uint8_t> login_data;
    const char* ncl_header = "NCL21075";
    login_data.insert(login_data.end(), ncl_header, ncl_header + strlen(ncl_header));
    int account_len = strlen(conn->account.c_str());
    if (account_len > 223) {
        login_data.push_back(255);
        login_data.insert(login_data.end(), conn->account.c_str() + 223, conn->account.c_str() + account_len);
    } else {
        login_data.push_back(32 + account_len);
        login_data.insert(login_data.end(), conn->account.c_str(), conn->account.c_str() + account_len);
    }
    int password_len = strlen(conn->password.c_str());
    if (password_len > 223) {
        login_data.push_back(255);
        login_data.insert(login_data.end(), conn->password.c_str() + 223, conn->password.c_str() + password_len);
    } else {
        login_data.push_back(32 + password_len);
        login_data.insert(login_data.end(), conn->password.c_str(), conn->password.c_str() + password_len);
    }
    std::vector<uint8_t> login_packet = conn->nc_protocol.sendPacket(PLI_NPCPROPS, login_data);
    if (!grc::sendAll(conn->nc_socket, login_packet.data(), login_packet.size())) {
        conn->setError("Failed to send NC login");
        closesocket(conn->nc_socket);
        conn->nc_socket = INVALID_SOCKET;
        return 0;
    }
    conn->nc_connected = true;
    conn->nc_recv_thread = std::thread(&RCConnection::ncRecvLoop, conn);
    return 1;
}
void rc_on_connected(RCHandle handle, RC_OnConnected callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_connected = callback;
    conn->on_connected_data = user_data;
}
void rc_on_disconnected(RCHandle handle, RC_OnDisconnected callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_disconnected = callback;
    conn->on_disconnected_data = user_data;
}
void rc_on_player_joined(RCHandle handle, RC_OnPlayerJoined callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_player_joined = callback;
    conn->on_player_joined_data = user_data;
}
void rc_on_player_left(RCHandle handle, RC_OnPlayerLeft callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_player_left = callback;
    conn->on_player_left_data = user_data;
}
void rc_on_message(RCHandle handle, RC_OnMessage callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_message = callback;
    conn->on_message_data = user_data;
}
void rc_on_private_message(RCHandle handle, RC_OnPrivateMessage callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_private_message = callback;
    conn->on_private_message_data = user_data;
}
void rc_on_file_received(RCHandle handle, RC_OnFileReceived callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_file_received = callback;
    conn->on_file_received_data = user_data;
}
void rc_on_weapon_added(RCHandle handle, RC_OnWeaponAdded callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_weapon_added = callback;
    conn->on_weapon_added_data = user_data;
}
void rc_on_weapon_deleted(RCHandle handle, RC_OnWeaponDeleted callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_weapon_deleted = callback;
    conn->on_weapon_deleted_data = user_data;
}
void rc_on_class_added(RCHandle handle, RC_OnClassAdded callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_class_added = callback;
    conn->on_class_added_data = user_data;
}
void rc_on_class_deleted(RCHandle handle, RC_OnClassDeleted callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_class_deleted = callback;
    conn->on_class_deleted_data = user_data;
}
void rc_on_npc_added(RCHandle handle, RC_OnNPCAdded callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_npc_added = callback;
    conn->on_npc_added_data = user_data;
}
void rc_on_npc_deleted(RCHandle handle, RC_OnNPCDeleted callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_npc_deleted = callback;
    conn->on_npc_deleted_data = user_data;
}
void rc_on_npc_attributes(RCHandle handle, RC_OnNPCAttributes callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_npc_attributes = callback;
    conn->on_npc_attributes_data = user_data;
}
void rc_on_player_prop_changed(RCHandle handle, RC_OnPlayerPropChanged callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_player_prop_changed = callback;
    conn->on_player_prop_changed_data = user_data;
}
void rc_on_world_time(RCHandle handle, RC_OnWorldTime callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_world_time = callback;
    conn->on_world_time_data = user_data;
}
void rc_on_max_upload_file_size(RCHandle handle, RC_OnMaxUploadFileSize callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_max_upload_file_size = callback;
    conn->on_max_upload_file_size_data = user_data;
}
void rc_on_command_response(RCHandle handle, RC_OnCommandResponse callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_command_response = callback;
    conn->on_command_response_data = user_data;
}
void rc_on_raw_packet(RCHandle handle, RC_OnRawPacket callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_raw_packet = callback;
    conn->on_raw_packet_data = user_data;
}
void rc_on_pm_servers_updated(RCHandle handle, RC_OnPMServersUpdated callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_pm_servers_updated = callback;
    conn->on_pm_servers_updated_data = user_data;
}
void rc_on_npc_flags(RCHandle handle, RC_OnNPCFlags callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_npc_flags = callback;
    conn->on_npc_flags_data = user_data;
}
void rc_on_pm_server_players(RCHandle handle, RC_OnPMServerPlayers callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_pm_server_players = callback;
    conn->on_pm_server_players_data = user_data;
}
void rc_on_filebrowser_folders(RCHandle handle, RC_OnFileBrowserFolders callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_filebrowser_folders = callback;
    conn->on_filebrowser_folders_data = user_data;
}
void rc_on_filebrowser_files(RCHandle handle, RC_OnFileBrowserFiles callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_filebrowser_files = callback;
    conn->on_filebrowser_files_data = user_data;
}
void rc_on_filebrowser_message(RCHandle handle, RC_OnFileBrowserMessage callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_filebrowser_message = callback;
    conn->on_filebrowser_message_data = user_data;
}
void rc_on_script_received(RCHandle handle, RC_OnScriptReceived callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_script_received = callback;
    conn->on_script_received_data = user_data;
}
void rc_on_server_data(RCHandle handle, RC_OnServerData callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_server_data = callback;
    conn->on_server_data_data = user_data;
}
void rc_on_player_rights(RCHandle handle, RC_OnPlayerRights callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_player_rights = callback;
    conn->on_player_rights_data = user_data;
}
void rc_on_player_text_data(RCHandle handle, RC_OnPlayerTextData callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_player_text_data = callback;
    conn->on_player_text_data_data = user_data;
}
void rc_on_player_attributes(RCHandle handle, RC_OnPlayerAttributes callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_player_attributes = callback;
    conn->on_player_attributes_data = user_data;
}
void rc_on_local_npcs(RCHandle handle, RC_OnLocalNPCs callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_local_npcs = callback;
    conn->on_local_npcs_data = user_data;
}
void rc_on_irc_message(RCHandle handle, RC_OnIrcMessage callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_irc_message = callback;
    conn->on_irc_message_data = user_data;
}
void rc_on_ban_data(RCHandle handle, RC_OnBanData callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_ban_data = callback;
    conn->on_ban_data_data = user_data;
}
void rc_on_ban_list_data(RCHandle handle, RC_OnBanListData callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_ban_list_data = callback;
    conn->on_ban_list_data_data = user_data;
}
void rc_on_account_list(RCHandle handle, RC_OnAccountList callback, void* user_data) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->on_account_list = callback;
    conn->on_account_list_data = user_data;
}
int rc_get_players(RCHandle handle, RCPlayer** players_out) {
    if (!handle || !players_out) return 0;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    *players_out = conn->player_cache.data();
    return conn->player_cache.size();
}
int rc_get_weapons(RCHandle handle, RCWeapon** weapons_out) {
    if (!handle || !weapons_out) return 0;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    *weapons_out = conn->weapon_cache.data();
    return conn->weapon_cache.size();
}
int rc_get_classes(RCHandle handle, RCClass** classes_out) {
    if (!handle || !classes_out) return 0;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    *classes_out = conn->class_cache.data();
    return conn->class_cache.size();
}
int rc_get_npcs(RCHandle handle, RCNPC** npcs_out) {
    if (!handle || !npcs_out) return 0;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    *npcs_out = conn->npc_cache.data();
    return conn->npc_cache.size();
}
int rc_get_levels(RCHandle handle, RCLevel** levels_out) {
    if (!handle || !levels_out) return 0;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    *levels_out = conn->level_cache.data();
    return conn->level_cache.size();
}
int rc_get_pm_servers(RCHandle handle, const char*** servers_out) {
    if (!handle || !servers_out) return 0;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    conn->pm_server_ptr_cache.clear();
    for (const auto& server_name : conn->pm_server_cache) {
        conn->pm_server_ptr_cache.push_back(server_name.c_str());
    }
    *servers_out = conn->pm_server_ptr_cache.data();
    return static_cast<int>(conn->pm_server_ptr_cache.size());
}
char* rc_get_cached_npc_flags(RCHandle handle, int npc_id) {
    if (!handle) return nullptr;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    auto it = conn->npc_flags_cache.find(npc_id);
    if (it == conn->npc_flags_cache.end()) return nullptr;
    return grcStrdup(it->second.c_str());
}
int rc_get_filebrowser_folders(RCHandle handle, RCFileBrowserFolder** folders_out) {
    if (!handle || !folders_out) return 0;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    conn->clearFileBrowserFolderView();
    for (auto& folder : conn->filebrowser_folders) {
        RCFileBrowserFolder item;
        item.rights = grcStrdup(folder.rights.c_str());
        item.pattern = grcStrdup(folder.pattern.c_str());
        conn->filebrowser_folder_view.push_back(item);
    }
    *folders_out = conn->filebrowser_folder_view.data();
    return static_cast<int>(conn->filebrowser_folder_view.size());
}
int rc_get_filebrowser_files(RCHandle handle, RCFileBrowserEntry** entries_out) {
    if (!handle || !entries_out) return 0;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    conn->clearFileBrowserFileView();
    for (auto& file : conn->filebrowser_files) {
        RCFileBrowserEntry item;
        item.path = grcStrdup(file.path.c_str());
        item.rights = grcStrdup(file.rights.c_str());
        item.size = file.size;
        item.modified = file.modified;
        item.is_directory = file.is_directory;
        conn->filebrowser_file_view.push_back(item);
    }
    *entries_out = conn->filebrowser_file_view.data();
    return static_cast<int>(conn->filebrowser_file_view.size());
}
int rc_copy_filebrowser_folders(RCHandle handle, RCFileBrowserFolder** folders_out) {
    if (!handle || !folders_out) return 0;
    *folders_out = nullptr;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    int count = static_cast<int>(conn->filebrowser_folders.size());
    if (count <= 0) return 0;
    RCFileBrowserFolder* folders = static_cast<RCFileBrowserFolder*>(calloc(count, sizeof(RCFileBrowserFolder)));
    if (!folders) return 0;
    for (int i = 0; i < count; ++i) {
        folders[i].rights = grcStrdup(conn->filebrowser_folders[i].rights.c_str());
        folders[i].pattern = grcStrdup(conn->filebrowser_folders[i].pattern.c_str());
    }
    *folders_out = folders;
    return count;
}
int rc_copy_filebrowser_files(RCHandle handle, RCFileBrowserEntry** entries_out) {
    if (!handle || !entries_out) return 0;
    *entries_out = nullptr;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    int count = static_cast<int>(conn->filebrowser_files.size());
    if (count <= 0) return 0;
    validateHeap("before copy_files calloc");
    RCFileBrowserEntry* entries = static_cast<RCFileBrowserEntry*>(calloc(count, sizeof(RCFileBrowserEntry)));
    if (!entries) return 0;
    for (int i = 0; i < count; ++i) {
        entries[i].path = grcStrdup(conn->filebrowser_files[i].path.c_str());
        entries[i].rights = grcStrdup(conn->filebrowser_files[i].rights.c_str());
        entries[i].size = conn->filebrowser_files[i].size;
        entries[i].modified = conn->filebrowser_files[i].modified;
        entries[i].is_directory = conn->filebrowser_files[i].is_directory;
    }
    *entries_out = entries;
    validateHeap("after copy_files strdup loop");
    return count;
}
void rc_free_filebrowser_folders(RCFileBrowserFolder* folders, int count) {
    if (!folders) return;
    for (int i = 0; i < count; ++i) {
        if (folders[i].rights) free(folders[i].rights);
        if (folders[i].pattern) free(folders[i].pattern);
    }
    free(folders);
}
void rc_free_filebrowser_files(RCFileBrowserEntry* entries, int count) {
    if (!entries) return;
    validateHeap("before free_files");
    for (int i = 0; i < count; ++i) {
        if (entries[i].path) free(entries[i].path);
        if (entries[i].rights) free(entries[i].rights);
    }
    free(entries);
}
char* rc_get_server_options(RCHandle handle) {
    if (!handle) return nullptr;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    return grcStrdup(conn->server_options.c_str());
}
char* rc_get_server_flags(RCHandle handle) {
    if (!handle) return nullptr;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    return grcStrdup(conn->server_flags.c_str());
}
char* rc_get_folder_config(RCHandle handle) {
    if (!handle) return nullptr;
    RCConnection* conn = (RCConnection*)handle;
    std::lock_guard<std::mutex> lock(conn->cache_mutex);
    return grcStrdup(conn->folder_config.c_str());
}
long long rc_get_max_upload_file_size(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    return conn->max_upload_file_size;
}
int rc_execute(RCHandle handle, const char* command) {
    if (!handle || !command) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated) return 0;
    std::vector<uint8_t> data(command, command + strlen(command));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_CHAT, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_upload_file(RCHandle handle, const char* path, const char* content, int length) {
    if (!handle || !path || !content) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated) return 0;
    std::string filename = path;
    size_t slash = filename.find_last_of("/\\");
    if (slash != std::string::npos) filename = filename.substr(slash + 1);
    if (filename.empty() || filename.size() > 223) return 0;
    const int chunk_size = 49152;
    auto send_chunk = [&](const char* chunk, int chunk_len) -> bool {
        std::vector<uint8_t> inner;
        inner.push_back(PLI_RC_FILEBROWSER_UP + 32);
        inner.push_back(grc::writeGByte((int)filename.size()));
        inner.insert(inner.end(), filename.begin(), filename.end());
        inner.insert(inner.end(), chunk, chunk + chunk_len);
        inner.push_back(0x0a);
        std::vector<uint8_t> size_data;
        grc::writeGInt3(size_data, (int)inner.size());
        std::vector<uint8_t> raw_header = conn->protocol.sendPacket(PLI_RAWDATA, size_data);
        if (!grc::sendAll(conn->game_socket, raw_header.data(), raw_header.size())) return false;
        std::vector<uint8_t> raw_block = conn->protocol.rawBlock(inner);
        return grc::sendAll(conn->game_socket, raw_block.data(), raw_block.size());
    };
    if (length <= chunk_size) return send_chunk(content, length) ? 1 : 0;
    std::vector<uint8_t> start_data(filename.begin(), filename.end());
    std::vector<uint8_t> start_packet = conn->protocol.sendPacket(PLI_RC_LARGEFILESTART, start_data);
    if (!grc::sendAll(conn->game_socket, start_packet.data(), start_packet.size())) return 0;
    for (int offset = 0; offset < length; offset += chunk_size) {
        int remaining = length - offset;
        int chunk_len = remaining < chunk_size ? remaining : chunk_size;
        if (!send_chunk(content + offset, chunk_len)) return 0;
        if (conn->on_filebrowser_message) {
            std::string msg = "Uploaded chunk: " + std::to_string(offset + chunk_len) + "/" + std::to_string(length) + " bytes for " + filename;
            conn->pushEvent([conn, msg]() { conn->on_filebrowser_message(msg.c_str(), conn->on_filebrowser_message_data); });
        }
    }
    std::vector<uint8_t> end_packet = conn->protocol.sendPacket(PLI_RC_LARGEFILEEND, start_data);
    return grc::sendAll(conn->game_socket, end_packet.data(), end_packet.size()) ? 1 : 0;
}
int rc_download_file(RCHandle handle, const char* path) {
    if (!handle || !path) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated) return 0;
    {
        std::lock_guard<std::mutex> lock(conn->transfer_mutex);
        conn->file_transfers.clear();
        conn->pending_file_download = path;
    }
    std::vector<uint8_t> data(path, path + strlen(path));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_FILEBROWSER_DOWN, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_warp_player(RCHandle handle, int player_id, const char* level, float x, float y) {
    if (!handle || !level) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated) return 0;
    std::vector<uint8_t> data;
    grc::writeGShort(data, player_id);
    data.push_back(grc::writeGByte((int)(x * 2)));
    data.push_back(grc::writeGByte((int)(y * 2)));
    data.insert(data.end(), level, level + strlen(level));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_WARPPLAYER, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_disconnect_player(RCHandle handle, int player_id, const char* reason) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated) return 0;
    std::vector<uint8_t> data;
    grc::writeGShort(data, player_id);
    if (reason) data.insert(data.end(), reason, reason + strlen(reason));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_DISCONNECTPLAYER, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_add_weapon(RCHandle handle, const char* name, const char* image, const char* script) {
    if (!handle || !name || !image || !script) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected || !conn->nc_authenticated) return 0;
    std::vector<uint8_t> data;
    data.push_back(grc::writeGByte(strlen(name)));
    data.insert(data.end(), name, name + strlen(name));
    data.push_back(grc::writeGByte(strlen(image)));
    data.insert(data.end(), image, image + strlen(image));
    // Weapons use simple tokenization: strip \r and replace \n with §
    std::string tokenized = script;
    tokenized.erase(std::remove(tokenized.begin(), tokenized.end(), '\r'), tokenized.end());
    std::replace(tokenized.begin(), tokenized.end(), '\n', '\xa7');
    data.insert(data.end(), tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_WEAPONADD, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_delete_weapon(RCHandle handle, const char* name) {
    if (!handle || !name) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected || !conn->nc_authenticated) return 0;
    std::vector<uint8_t> data(name, name + strlen(name));
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_WEAPONDELETE, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_update_weapon(RCHandle handle, const char* name, const char* image, const char* script) {
    if (!handle || !name || !image || !script) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected || !conn->nc_authenticated) return 0;
    std::vector<uint8_t> data;
    data.push_back(grc::writeGByte(strlen(name)));
    data.insert(data.end(), name, name + strlen(name));
    data.push_back(grc::writeGByte(strlen(image)));
    data.insert(data.end(), image, image + strlen(image));
    // Weapons use simple tokenization: strip \r and replace \n with §
    std::string tokenized = script;
    tokenized.erase(std::remove(tokenized.begin(), tokenized.end(), '\r'), tokenized.end());
    std::replace(tokenized.begin(), tokenized.end(), '\n', '\xa7');
    data.insert(data.end(), tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_WEAPONADD, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_add_class(RCHandle handle, const char* name, const char* script) {
    if (!handle || !name || !script) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected || !conn->nc_authenticated) return 0;
    std::vector<uint8_t> data;
    data.push_back(grc::writeGByte(strlen(name)));
    data.insert(data.end(), name, name + strlen(name));
    std::string tokenized = grc::gtokenizeString(script);
    data.insert(data.end(), tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_CLASSADD, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_delete_class(RCHandle handle, const char* name) {
    if (!handle || !name) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected || !conn->nc_authenticated) return 0;
    std::vector<uint8_t> data(name, name + strlen(name));
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_CLASSDELETE, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_update_class(RCHandle handle, const char* name, const char* script) {
    if (!handle || !name || !script) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected || !conn->nc_authenticated) return 0;
    std::vector<uint8_t> data;
    data.push_back(grc::writeGByte(strlen(name)));
    data.insert(data.end(), name, name + strlen(name));
    std::string tokenized = grc::gtokenizeString(script);
    data.insert(data.end(), tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_CLASSADD, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_delete_npc(RCHandle handle, int npc_id) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected || !conn->nc_authenticated) return 0;
    std::vector<uint8_t> data;
    grc::writeGInt3(data, npc_id);
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_NPCDELETE, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_update_npc(RCHandle handle, int npc_id, const char* script) {
    if (!handle || !script) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected || !conn->nc_authenticated) return 0;
    std::vector<uint8_t> data;
    grc::writeGInt3(data, npc_id);
    std::string tokenized = grc::gtokenizeString(script);
    data.insert(data.end(), tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_NPCSCRIPTSET, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_create_npc_on_server(RCHandle handle, const char* name, int npc_id, const char* type, const char* scripter, const char* level, const char* x, const char* y) {
    if (!handle || !name || !type || !scripter || !level || !x || !y) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated || !conn->nc_connected) return 0;
    std::string info = std::string(name) + "\n" + std::to_string(npc_id) + "\n" + type + "\n" + scripter + "\n" + level + "\n" + x + "\n" + y;
    std::string tokenized = grc::gtokenizeString(info);
    std::vector<uint8_t> data(tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_NPCADD, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_disconnect_nc(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected) return 0;
    if (conn->nc_socket != INVALID_SOCKET) {
        closesocket(conn->nc_socket);
        conn->nc_socket = INVALID_SOCKET;
    }
    if (conn->nc_recv_thread.joinable()) conn->nc_recv_thread.join();
    conn->nc_connected = false;
    return 1;
}
int rc_set_nickname(RCHandle handle, const char* nickname) {
    if (!handle || !nickname) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated) return 0;
    std::vector<uint8_t> data;
    data.push_back(' ');
    int nick_len = strlen(nickname);
    if (nick_len > 223) {
        data.push_back(255);
        data.insert(data.end(), nickname + 223, nickname + nick_len);
    } else {
        data.push_back(32 + nick_len);
        data.insert(data.end(), nickname, nickname + nick_len);
    }
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_PLAYERPROPS, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_upload_level(RCHandle handle, const char* level_name, const char* content, int length) {
    return rc_upload_file(handle, level_name, content, length);
}
int rc_download_level(RCHandle handle, const char* level_name) {
    if (!handle || !level_name) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated) return 0;
    std::vector<uint8_t> data(level_name, level_name + strlen(level_name));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_FILEBROWSER_DOWN, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_pm_server_list(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated) return 0;
    std::string request = protocolTextNamespace() + "\npmservers\nall\n";
    std::string tokenized = grc::gtokenizeString(request);
    std::vector<uint8_t> data(tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_REQUESTTEXT, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_send_toall_message(RCHandle handle, const char* message) {
    if (!handle || !message) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->connected || !conn->authenticated) return 0;
    size_t message_len = strlen(message);
    if (message_len > 223) return 0;
    std::vector<uint8_t> data;
    data.push_back(grc::writeGByte(static_cast<int>(message_len)));
    data.insert(data.end(), message, message + message_len);
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_TOALL, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_npc_script(RCHandle handle, int npc_id) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    int high = ((npc_id >> 14) & 0xFF) + 32;
    int mid = ((npc_id >> 7) & 0x7F) + 32;
    int low = (npc_id & 0x7F) + 32;
    std::vector<uint8_t> data = {(uint8_t)high, (uint8_t)mid, (uint8_t)low};
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_NPCSCRIPTGET, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_npc_attributes(RCHandle handle, int npc_id) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    conn->pending_npc_attributes_id = npc_id;
    int high = ((npc_id >> 14) & 0xFF) + 32;
    int mid = ((npc_id >> 7) & 0x7F) + 32;
    int low = (npc_id & 0x7F) + 32;
    std::vector<uint8_t> data = {(uint8_t)high, (uint8_t)mid, (uint8_t)low};
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_NPCGET, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_class_script(RCHandle handle, const char* class_name) {
    if (!handle || !class_name) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(class_name, class_name + strlen(class_name));
    data.push_back('\n');
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_CLASSEDIT, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_weapon_script(RCHandle handle, const char* weapon_name) {
    if (!handle || !weapon_name) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(weapon_name, weapon_name + strlen(weapon_name));
    data.push_back('\n');
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_WEAPONGET, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_reset_npc(RCHandle handle, int npc_id) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    int high = ((npc_id >> 14) & 0xFF) + 32;
    int mid = ((npc_id >> 7) & 0x7F) + 32;
    int low = (npc_id & 0x7F) + 32;
    std::vector<uint8_t> data = {(uint8_t)high, (uint8_t)mid, (uint8_t)low};
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_NPCRESET, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_warp_npc(RCHandle handle, int npc_id, float x, float y, const char* level) {
    if (!handle || !level) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    int high = ((npc_id >> 14) & 0xFF) + 32;
    int mid = ((npc_id >> 7) & 0x7F) + 32;
    int low = (npc_id & 0x7F) + 32;
    std::vector<uint8_t> data = {(uint8_t)high, (uint8_t)mid, (uint8_t)low};
    int x_val = (int)(x * 2);
    int y_val = (int)(y * 2);
    data.push_back((uint8_t)x_val);
    data.push_back((uint8_t)y_val);
    data.insert(data.end(), level, level + strlen(level));
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_NPCWARP, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_get_npc_flags(RCHandle handle, int npc_id) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    int high = ((npc_id >> 14) & 0xFF) + 32;
    int mid = ((npc_id >> 7) & 0x7F) + 32;
    int low = (npc_id & 0x7F) + 32;
    std::vector<uint8_t> data = {(uint8_t)high, (uint8_t)mid, (uint8_t)low};
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_NPCFLAGSGET, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_set_npc_flags(RCHandle handle, int npc_id, const char* flags) {
    if (!handle || !flags) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    int high = ((npc_id >> 14) & 0xFF) + 32;
    int mid = ((npc_id >> 7) & 0x7F) + 32;
    int low = (npc_id & 0x7F) + 32;
    std::vector<uint8_t> data = {(uint8_t)high, (uint8_t)mid, (uint8_t)low};
    std::string tokenized = grc::gtokenizeString(flags);
    data.insert(data.end(), tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_NPCFLAGSSET, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_player_rights(RCHandle handle, const char* account) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(account, account + strlen(account));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PLAYERRIGHTSGET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_player_attrs(RCHandle handle, const char* account) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    data.push_back(grc::writeGByte(strlen(account)));
    data.insert(data.end(), account, account + strlen(account));
    data.push_back(grc::writeGByte(0));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PLAYERPROPSGET3, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_player_account(RCHandle handle, const char* account) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(account, account + strlen(account));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_ACCOUNTGET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_account_list(RCHandle handle, const char* account_filter, const char* conditions) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    writeRcLenString(data, trimText(account_filter ? account_filter : ""));
    writeRcLenString(data, trimText(conditions ? conditions : ""));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_ACCOUNTLISTGET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_player_comments(RCHandle handle, const char* account) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(account, account + strlen(account));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PLAYERCOMMENTSGET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_player_profile(RCHandle handle, const char* account) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(account, account + strlen(account));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_PROFILEGET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_send_private_message(RCHandle handle, int player_id, const char* message) {
    if (!handle || !message) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    grc::writeGShort(data, 1);
    grc::writeGShort(data, player_id);
    std::string tokenized = grc::gtokenizeString(message);
    data.insert(data.end(), tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_PRIVATEMESSAGE, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_send_admin_message(RCHandle handle, int player_id, const char* message) {
    if (!handle || !message) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    grc::writeGShort(data, player_id);
    std::string msg_str(message);
    data.insert(data.end(), msg_str.begin(), msg_str.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PRIVADMINMESSAGE, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_send_admin_message_all(RCHandle handle, const char* message) {
    if (!handle || !message) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    std::string msg_str(message);
    data.insert(data.end(), msg_str.begin(), msg_str.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_ADMINMESSAGE, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_reset_player(RCHandle handle, const char* account) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(account, account + strlen(account));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PLAYERPROPSRESET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_send_nc_packet(RCHandle handle, int packet_id, const char* data, int length) {
    if (!handle || !data || length < 0) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> payload(data, data + length);
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(packet_id, payload);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}
char* rc_gtokenize(const char* text) {
    if (!text) return nullptr;
    std::string result = grc::gtokenizeString(text);
    return grcStrdup(result.c_str());
}
char* rc_gtokenize_reverse(const char* content) {
    if (!content) return nullptr;
    std::string result = grc::gtokenizeReverseString(content);
    return grcStrdup(result.c_str());
}
GRCLIB_API char* rc_get_1plus_text_net_string(const char* text) {
    if (!text) return nullptr;
    std::string s(text);
    if (s.length() > 223) return grcStrdup((std::string(1, (char)255) + s.substr(223)).c_str());
    return grcStrdup((std::string(1, (char)(32 + s.length())) + s).c_str());
}
GRCLIB_API int rc_read_gbyte(const char* data, int length, int offset, int* value_out, int* offset_out) {
    if (!data || !value_out || !offset_out || offset < 0 || offset >= length) return 0;
    *value_out = (((uint8_t)data[offset]) & 0xFF) - 0x20;
    *offset_out = offset + 1;
    return 1;
}
GRCLIB_API int rc_read_gshort(const char* data, int length, int offset, int* value_out, int* offset_out) {
    if (!data || !value_out || !offset_out || offset < 0 || offset + 2 > length) return 0;
    *value_out = ((((uint8_t)data[offset]) - 32) << 7) + (((uint8_t)data[offset+1]) - 32);
    *offset_out = offset + 2;
    return 1;
}
GRCLIB_API int rc_read_gint5(const char* data, int length, int offset, int* value_out, int* offset_out) {
    if (!data || !value_out || !offset_out || offset < 0 || offset + 5 > length) return 0;
    int value = (((uint8_t)data[offset]) - 32) << 28;
    value += (((uint8_t)data[offset+1]) - 32) << 21;
    value += (((uint8_t)data[offset+2]) - 32) << 14;
    value += (((uint8_t)data[offset+3]) - 32) << 7;
    value += ((uint8_t)data[offset+4]) - 32;
    *value_out = value;
    *offset_out = offset + 5;
    return 1;
}
GRCLIB_API char* rc_read_length_string(const char* data, int length, int offset, int* offset_out) {
    if (!data || !offset_out || offset < 0 || offset >= length) return nullptr;
    int str_len = (((uint8_t)data[offset]) & 0xFF) - 0x20;
    offset++;
    if (offset + str_len > length) return nullptr;
    std::string result(data + offset, str_len);
    *offset_out = offset + str_len;
    if (result.empty()) return nullptr;
    return grcStrdup(result.c_str());
}
GRCLIB_API char* rc_read_comma_text(const char* data, int length, int offset, int read_length) {
    if (!data || offset < 0 || offset >= length) return nullptr;
    int actual_len = (read_length < 0) ? (length - offset) : read_length;
    if (offset + actual_len > length) return nullptr;
    std::string text(data + offset, actual_len);
    std::vector<uint8_t> text_vec(text.begin(), text.end());
    size_t off = 0;
    std::string result = grc::readCommaText(text_vec, off, actual_len);
    if (result.empty()) return nullptr;
    return grcStrdup(result.c_str());
}
int rc_filebrowser_start(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    {
        std::lock_guard<std::mutex> lock(conn->cache_mutex);
        conn->filebrowser_folders.clear();
        conn->filebrowser_files.clear();
        conn->clearFileBrowserFolderView();
        conn->clearFileBrowserFileView();
    }
    std::vector<uint8_t> data;
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_FILEBROWSER_START, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_filebrowser_cd(RCHandle handle, const char* folder_path) {
    if (!handle || !folder_path) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(folder_path, folder_path + strlen(folder_path));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_FILEBROWSER_CD, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_filebrowser_download(RCHandle handle, const char* file_path) {
    if (!handle || !file_path) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    {
        std::lock_guard<std::mutex> lock(conn->transfer_mutex);
        conn->file_transfers.clear();
        conn->pending_file_download = file_path;
    }
    std::vector<uint8_t> data(file_path, file_path + strlen(file_path));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_FILEBROWSER_DOWN, data);
    int result = grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
    return result;
}
int rc_filebrowser_delete(RCHandle handle, const char* file_path) {
    if (!handle || !file_path) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(file_path, file_path + strlen(file_path));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_FILEBROWSER_DELETE, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_filebrowser_rename(RCHandle handle, const char* old_path, const char* new_path) {
    if (!handle || !old_path || !new_path) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    size_t old_len = strlen(old_path);
    size_t new_len = strlen(new_path);
    if (old_len > 223 || new_len > 223) return 0;
    std::vector<uint8_t> data;
    data.reserve(old_len + new_len + 2);
    data.push_back(static_cast<uint8_t>(old_len + 32));
    data.insert(data.end(), old_path, old_path + old_len);
    data.push_back(static_cast<uint8_t>(new_len + 32));
    data.insert(data.end(), new_path, new_path + new_len);
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_FILEBROWSER_RENAME, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_server_options(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_SERVEROPTIONSGET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_upload_server_options(RCHandle handle, const char* content) {
    if (!handle || !content) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::string tokenized = grc::gtokenizeString(content);
    std::vector<uint8_t> data(tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_SERVEROPTIONSSET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_server_flags(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_SERVERFLAGSGET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_upload_server_flags(RCHandle handle, const char* content) {
    if (!handle || !content) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<std::string> lines;
    std::stringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!trimText(line).empty()) lines.push_back(line.size() > 223 ? line.substr(0, 223) : line);
    }
    std::vector<uint8_t> data;
    data.push_back((uint8_t)(((lines.size() >> 7) & 0xff) + 32));
    data.push_back((uint8_t)((lines.size() & 0x7f) + 32));
    for (const auto& item : lines) writeAttrString(data, item);
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_SERVERFLAGSSET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_folder_config(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_FOLDERCONFIGGET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_upload_folder_config(RCHandle handle, const char* content) {
    if (!handle || !content) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::string tokenized = grc::gtokenizeString(content);
    std::vector<uint8_t> data(tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_FOLDERCONFIGSET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_request_pm_server_players(RCHandle handle, const char* server_name) {
    if (!handle || !server_name) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::string request = protocolTextNamespace() + "\npmserverplayers\n" + std::string(server_name) + "\n";
    std::string tokenized = grc::gtokenizeString(request);
    std::vector<uint8_t> data(tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_REQUESTTEXT, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
const char* rc_last_error(RCHandle handle) {
    if (!handle) return "Invalid handle";
    RCConnection* conn = (RCConnection*)handle;
    return conn->getError().c_str();
}
void rc_free(void* ptr) {
    if (ptr) free(ptr);
}

char* rc_get_rights_names() {
    return dupText(joinLines(rightsNames()));
}

char* rc_get_color_names() {
    return dupText(joinLines(colorNames()));
}

char* rc_get_packet_names(int nc, int direction) {
    if (nc) {
        if (direction == 1) {
            return dupText(packetMapToText({
                PACKET_NAME_PAIR(PLI_NPCPROPS),
                PACKET_NAME_PAIR(PLI_NC_NPCGET), PACKET_NAME_PAIR(PLI_NC_NPCDELETE), PACKET_NAME_PAIR(PLI_NC_NPCRESET),
                PACKET_NAME_PAIR(PLI_NC_NPCSCRIPTGET), PACKET_NAME_PAIR(PLI_NC_NPCWARP), PACKET_NAME_PAIR(PLI_NC_NPCFLAGSGET),
                PACKET_NAME_PAIR(PLI_NC_NPCSCRIPTSET), PACKET_NAME_PAIR(PLI_NC_NPCFLAGSSET), PACKET_NAME_PAIR(PLI_NC_NPCADD),
                PACKET_NAME_PAIR(PLI_NC_CLASSEDIT), PACKET_NAME_PAIR(PLI_NC_CLASSADD), PACKET_NAME_PAIR(PLI_NC_LOCALNPCSGET),
                PACKET_NAME_PAIR(PLI_NC_WEAPONLISTGET), PACKET_NAME_PAIR(PLI_NC_WEAPONGET), PACKET_NAME_PAIR(PLI_NC_WEAPONADD),
                PACKET_NAME_PAIR(PLI_NC_WEAPONDELETE), PACKET_NAME_PAIR(PLI_NC_CLASSDELETE), PACKET_NAME_PAIR(PLI_NC_LEVELLISTGET),
                PACKET_NAME_PAIR(PLI_NC_LEVELLISTSET)
            }));
        }
        return dupText(packetMapToText({
            PACKET_NAME_PAIR(PLO_NC_NPCATTRIBUTES), PACKET_NAME_PAIR(PLO_NC_NPCADD), PACKET_NAME_PAIR(PLO_NC_NPCDELETE),
            PACKET_NAME_PAIR(PLO_NC_NPCSCRIPT), PACKET_NAME_PAIR(PLO_NC_NPCFLAGS), PACKET_NAME_PAIR(PLO_NC_CLASSGET),
            PACKET_NAME_PAIR(PLO_NC_CLASSADD), PACKET_NAME_PAIR(PLO_NC_LEVELDUMP), PACKET_NAME_PAIR(PLO_NC_WEAPONLISTGET),
            PACKET_NAME_PAIR(PLO_NC_CLASSDELETE), PACKET_NAME_PAIR(PLO_NC_WEAPONGET)
        }));
    }

    if (direction == 1) {
        return dupText(packetMapToText({
            PACKET_NAME_PAIR(PLI_TOALL), PACKET_NAME_PAIR(PLI_RAWDATA), PACKET_NAME_PAIR(PLI_RC_SERVEROPTIONSGET),
            PACKET_NAME_PAIR(PLI_RC_SERVEROPTIONSSET), PACKET_NAME_PAIR(PLI_RC_FOLDERCONFIGGET), PACKET_NAME_PAIR(PLI_RC_FOLDERCONFIGSET),
            PACKET_NAME_PAIR(PLI_RC_RESPAWNSET), PACKET_NAME_PAIR(PLI_RC_HORSELIFESET), PACKET_NAME_PAIR(PLI_RC_APINCREMENTSET),
            PACKET_NAME_PAIR(PLI_RC_BADDYRESPAWNSET), PACKET_NAME_PAIR(PLI_RC_PLAYERPROPSGET), PACKET_NAME_PAIR(PLI_RC_PLAYERPROPSSET),
            PACKET_NAME_PAIR(PLI_PRIVATEMESSAGE), PACKET_NAME_PAIR(PLI_RC_DISCONNECTPLAYER), PACKET_NAME_PAIR(PLI_RC_UPDATELEVELS),
            PACKET_NAME_PAIR(PLI_RC_ADMINMESSAGE), PACKET_NAME_PAIR(PLI_RC_PRIVADMINMESSAGE), PACKET_NAME_PAIR(PLI_RC_LISTRCS),
            PACKET_NAME_PAIR(PLI_RC_DISCONNECTRC), PACKET_NAME_PAIR(PLI_RC_APPLYREASON), PACKET_NAME_PAIR(PLI_RC_SERVERFLAGSGET),
            PACKET_NAME_PAIR(PLI_RC_SERVERFLAGSSET), PACKET_NAME_PAIR(PLI_RC_ACCOUNTADD), PACKET_NAME_PAIR(PLI_RC_ACCOUNTDEL),
            PACKET_NAME_PAIR(PLI_RC_ACCOUNTLISTGET), PACKET_NAME_PAIR(PLI_RC_PLAYERPROPSGET2), PACKET_NAME_PAIR(PLI_RC_PLAYERPROPSGET3),
            PACKET_NAME_PAIR(PLI_RC_PLAYERPROPSRESET), PACKET_NAME_PAIR(PLI_RC_PLAYERPROPSSET2), PACKET_NAME_PAIR(PLI_RC_ACCOUNTGET),
            PACKET_NAME_PAIR(PLI_RC_ACCOUNTSET), PACKET_NAME_PAIR(PLI_RC_CHAT), PACKET_NAME_PAIR(PLI_PROFILEGET),
            PACKET_NAME_PAIR(PLI_PROFILESET), PACKET_NAME_PAIR(PLI_RC_WARPPLAYER), PACKET_NAME_PAIR(PLI_RC_PLAYERRIGHTSGET),
            PACKET_NAME_PAIR(PLI_RC_PLAYERRIGHTSSET), PACKET_NAME_PAIR(PLI_RC_PLAYERCOMMENTSGET), PACKET_NAME_PAIR(PLI_RC_PLAYERCOMMENTSSET),
            PACKET_NAME_PAIR(PLI_RC_PLAYERBANGET), PACKET_NAME_PAIR(PLI_RC_PLAYERBANSET), PACKET_NAME_PAIR(PLI_RC_FILEBROWSER_START),
            PACKET_NAME_PAIR(PLI_RC_FILEBROWSER_CD), PACKET_NAME_PAIR(PLI_RC_FILEBROWSER_END), PACKET_NAME_PAIR(PLI_RC_FILEBROWSER_DOWN),
            PACKET_NAME_PAIR(PLI_RC_FILEBROWSER_UP), PACKET_NAME_PAIR(PLI_NPCSERVERQUERY), PACKET_NAME_PAIR(PLI_RC_FILEBROWSER_MOVE),
            PACKET_NAME_PAIR(PLI_RC_FILEBROWSER_DELETE), PACKET_NAME_PAIR(PLI_RC_FILEBROWSER_RENAME), PACKET_NAME_PAIR(PLI_NC_LISTNPCS),
            PACKET_NAME_PAIR(PLI_NC_NPCGET), PACKET_NAME_PAIR(PLI_NC_NPCDELETE), PACKET_NAME_PAIR(PLI_NC_NPCRESET),
            PACKET_NAME_PAIR(PLI_NC_NPCSCRIPTGET), PACKET_NAME_PAIR(PLI_NC_NPCWARP), PACKET_NAME_PAIR(PLI_NC_NPCFLAGSGET),
            PACKET_NAME_PAIR(PLI_NC_NPCSCRIPTSET), PACKET_NAME_PAIR(PLI_NC_NPCFLAGSSET), PACKET_NAME_PAIR(PLI_NC_NPCADD),
            PACKET_NAME_PAIR(PLI_NC_CLASSEDIT), PACKET_NAME_PAIR(PLI_NC_CLASSADD), PACKET_NAME_PAIR(PLI_NC_LOCALNPCSGET),
            PACKET_NAME_PAIR(PLI_NC_WEAPONLISTGET), PACKET_NAME_PAIR(PLI_NC_WEAPONGET), PACKET_NAME_PAIR(PLI_NC_WEAPONADD),
            PACKET_NAME_PAIR(PLI_NC_WEAPONDELETE), PACKET_NAME_PAIR(PLI_NC_CLASSDELETE), PACKET_NAME_PAIR(PLI_REQUESTUPDATEBOARD),
            PACKET_NAME_PAIR(PLI_NC_LEVELLISTGET), PACKET_NAME_PAIR(PLI_NC_LEVELLISTSET), PACKET_NAME_PAIR(PLI_REQUESTTEXT),
            PACKET_NAME_PAIR(PLI_SENDTEXT), PACKET_NAME_PAIR(PLI_RC_LARGEFILESTART), PACKET_NAME_PAIR(PLI_RC_LARGEFILEEND),
            PACKET_NAME_PAIR(PLI_UPDATEGANI), PACKET_NAME_PAIR(PLI_UPDATESCRIPT), PACKET_NAME_PAIR(PLI_UPDATEPACKAGEREQUESTFILE),
            PACKET_NAME_PAIR(PLI_RC_FOLDERDELETE), PACKET_NAME_PAIR(PLI_UPDATECLASS)
        }));
    }

    return dupText(packetMapToText({
        PACKET_NAME_PAIR(PLO_OTHERPLPROPS), PACKET_NAME_PAIR(PLO_PLAYERPROPS), PACKET_NAME_PAIR(PLO_BOMBADD), PACKET_NAME_PAIR(PLO_TOALL), PACKET_NAME_PAIR(PLO_FILESENDFAILED),
        PACKET_NAME_PAIR(PLO_NEWWORLDTIME), PACKET_NAME_PAIR(PLO_RC_ADMINMESSAGE), PACKET_NAME_PAIR(PLO_RC_ACCOUNTADD),
        PACKET_NAME_PAIR(PLO_RC_ACCOUNTSTATUS), PACKET_NAME_PAIR(PLO_RC_ACCOUNTNAME), PACKET_NAME_PAIR(PLO_RC_ACCOUNTDEL),
        PACKET_NAME_PAIR(PLO_RC_ACCOUNTPROPS), PACKET_NAME_PAIR(PLO_ADDPLAYER), PACKET_NAME_PAIR(PLO_DELPLAYER),
        PACKET_NAME_PAIR(PLO_RC_ACCOUNTPROPSGET), PACKET_NAME_PAIR(PLO_RC_ACCOUNTCHANGE), PACKET_NAME_PAIR(PLO_RC_PLAYERPROPSCHANGE),
        PACKET_NAME_PAIR(PLO_UNKNOWN60), PACKET_NAME_PAIR(PLO_RC_SERVERFLAGSGET), PACKET_NAME_PAIR(PLO_RC_PLAYERRIGHTSGET),
        PACKET_NAME_PAIR(PLO_RC_PLAYERCOMMENTSGET), PACKET_NAME_PAIR(PLO_RC_PLAYERBANGET), PACKET_NAME_PAIR(PLO_RC_FILEBROWSER_DIRLIST),
        PACKET_NAME_PAIR(PLO_RC_FILEBROWSER_DIR), PACKET_NAME_PAIR(PLO_RC_FILEBROWSER_MESSAGE), PACKET_NAME_PAIR(PLO_LARGEFILESTART),
        PACKET_NAME_PAIR(PLO_LARGEFILEEND), PACKET_NAME_PAIR(PLO_RC_ACCOUNTLISTGET), PACKET_NAME_PAIR(PLO_RC_PLAYERPROPS),
        PACKET_NAME_PAIR(PLO_RC_PLAYERPROPSGET), PACKET_NAME_PAIR(PLO_RC_ACCOUNTGET), PACKET_NAME_PAIR(PLO_RC_CHAT),
        PACKET_NAME_PAIR(PLO_PROFILE), PACKET_NAME_PAIR(PLO_RC_SERVEROPTIONSGET), PACKET_NAME_PAIR(PLO_RC_FOLDERCONFIGGET),
        PACKET_NAME_PAIR(PLO_NC_CONTROL), PACKET_NAME_PAIR(PLO_NPCSERVERADDR), PACKET_NAME_PAIR(PLO_NC_LEVELLIST),
        PACKET_NAME_PAIR(PLO_SERVERTEXT), PACKET_NAME_PAIR(PLO_DISCMESSAGE), PACKET_NAME_PAIR(PLO_SIGNATURE),
        PACKET_NAME_PAIR(PLO_PRIVATEMESSAGE), PACKET_NAME_PAIR(PLO_STAFFGUILDS), PACKET_NAME_PAIR(PLO_LARGEFILESIZE),
        PACKET_NAME_PAIR(PLO_RAWDATA), PACKET_NAME_PAIR(PLO_BOARDPACKET), PACKET_NAME_PAIR(PLO_FILE), PACKET_NAME_PAIR(PLO_RC_MAXUPLOADFILESIZE),
        PACKET_NAME_PAIR(PLO_STATUSLIST), PACKET_NAME_PAIR(PLO_UNKNOWN190), PACKET_NAME_PAIR(PLO_CLEARWEAPONS)
    }));
}

int rc_set_player_rights(RCHandle handle, const char* account, int rights_value, const char* ip_range, const char* folder_access) {
    if (!handle || !account || !ip_range) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    size_t account_len = strlen(account);
    data.push_back(account_len + 32);
    data.insert(data.end(), account, account + account_len);
    grc::writeGInt5(data, rights_value);
    size_t ip_len = strlen(ip_range);
    data.push_back(ip_len + 32);
    data.insert(data.end(), ip_range, ip_range + ip_len);
    if (folder_access && strlen(folder_access) > 0) {
        std::string folder_commatext = grc::gtokenizeString(folder_access);
        size_t folder_len = folder_commatext.size();
        uint8_t high = ((folder_len >> 7) & 0xFF) + 32;
        uint8_t low = (folder_len & 0x7F) + 32;
        data.push_back(high);
        data.push_back(low);
        data.insert(data.end(), folder_commatext.begin(), folder_commatext.end());
    }
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PLAYERRIGHTSSET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
int rc_set_player_comments(RCHandle handle, const char* account, const char* comments) {
    if (!handle || !account || !comments) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    size_t account_len = strlen(account);
    data.push_back(account_len + 32);
    data.insert(data.end(), account, account + account_len);
    std::string comments_commatext = grc::gtokenizeString(comments);
    data.insert(data.end(), comments_commatext.begin(), comments_commatext.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PLAYERCOMMENTSSET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

int rc_set_player_attributes(RCHandle handle, const char* account_ptr, const char* properties_json_ptr) {
    if (!handle || !account_ptr || !properties_json_ptr) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::string json = properties_json_ptr;
    std::vector<uint8_t> props;
    auto addByte = [&](int id, const std::string& key) { if (jsonHasKey(json, key)) { props.push_back(grc::writeGByte(id)); props.push_back(grc::writeGByte((int)jsonGetNumber(json, key, 0))); } };
    auto addHalf = [&](int id, const std::string& key) { if (jsonHasKey(json, key)) { props.push_back(grc::writeGByte(id)); props.push_back(grc::writeGByte((int)(jsonGetNumber(json, key, 0) * 2))); } };
    auto addGInt3 = [&](int id, const std::string& key) { if (jsonHasKey(json, key)) { props.push_back(grc::writeGByte(id)); writeAttrGInt3(props, (int)jsonGetNumber(json, key, 0)); } };
    auto addString = [&](int id, const std::string& key) { if (jsonHasKey(json, key)) { props.push_back(grc::writeGByte(id)); writeAttrString(props, jsonGetString(json, key)); } };
    addByte(1, "1"); addHalf(2, "2"); addGInt3(3, "3"); addByte(4, "4"); addHalf(5, "5"); addHalf(6, "6");
    if (jsonHasKey(json, "sword_power") || jsonHasKey(json, "sword_image")) {
        int power = (int)jsonGetNumber(json, "sword_power", 0);
        std::string img = jsonGetString(json, "sword_image");
        props.push_back(grc::writeGByte(8));
        if (power == 0 && img.empty()) props.push_back(grc::writeGByte(0));
        else if (startsWithText(img, "sword") && img.size() > 9) {
            int idx = std::atoi(img.substr(5, img.size() - 9).c_str());
            if (idx >= 1 && idx <= 4) props.push_back(grc::writeGByte(idx));
            else { int encoded = power + 30; if (encoded < 10) encoded = 10; if (encoded > 50) encoded = 50; props.push_back(grc::writeGByte(encoded)); writeAttrString(props, img); }
        } else { int encoded = power + 30; if (encoded < 10) encoded = 10; if (encoded > 50) encoded = 50; props.push_back(grc::writeGByte(encoded)); writeAttrString(props, img); }
    }
    if (jsonHasKey(json, "shield_power") || jsonHasKey(json, "shield_image")) {
        int power = (int)jsonGetNumber(json, "shield_power", 0);
        std::string img = jsonGetString(json, "shield_image");
        props.push_back(grc::writeGByte(9));
        if (power == 0 && img.empty()) props.push_back(grc::writeGByte(0));
        else if (startsWithText(img, "shield") && img.size() > 10) {
            int idx = std::atoi(img.substr(6, img.size() - 10).c_str());
            if (idx >= 1 && idx <= 3) props.push_back(grc::writeGByte(idx));
            else { int encoded = power + 10; if (encoded < 10) encoded = 10; if (encoded > 13) encoded = 13; props.push_back(grc::writeGByte(encoded)); writeAttrString(props, img); }
        } else { int encoded = power + 10; if (encoded < 10) encoded = 10; if (encoded > 13) encoded = 13; props.push_back(grc::writeGByte(encoded)); writeAttrString(props, img); }
    }
    addString(10, "10");
    if (jsonHasKey(json, "head_image")) {
        std::string img = jsonGetString(json, "head_image");
        props.push_back(grc::writeGByte(11));
        if (startsWithText(img, "head") && img.size() > 8) {
            int idx = std::atoi(img.substr(4, img.size() - 8).c_str());
            if (idx >= 0 && idx < 100) props.push_back(grc::writeGByte(idx));
            else { props.push_back(grc::writeGByte(100 + (int)img.size())); props.insert(props.end(), img.begin(), img.end()); }
        } else if (!img.empty()) { props.push_back(grc::writeGByte(100 + (int)img.size())); props.insert(props.end(), img.begin(), img.end()); }
        else props.push_back(grc::writeGByte(0));
    }
    std::vector<int> colors = jsonGetIntArray(json, "colors");
    if (!colors.empty()) {
        props.push_back(grc::writeGByte(13));
        for (int i = 0; i < 5; ++i) props.push_back(grc::writeGByte(i < (int)colors.size() ? colors[i] : 0));
    }
    addString(15, "15"); addString(16, "16"); addByte(17, "17"); addByte(18, "18"); addByte(19, "19"); addString(20, "20"); addString(21, "21"); addByte(26, "26");
    addGInt3(27, "27"); addGInt3(28, "28"); addGInt3(29, "29"); addGInt3(30, "30"); addString(53, "body_image");
    if (jsonHasKey(json, "rating") && jsonHasKey(json, "rating_dev")) {
        int rating = (int)jsonGetNumber(json, "rating", 0), rating_dev = (int)jsonGetNumber(json, "rating_dev", 0);
        props.push_back(grc::writeGByte(36));
        props.push_back(grc::writeGByte((rating >> 5) & 0xff));
        props.push_back(grc::writeGByte(((rating & 0x1f) << 2) | ((rating_dev >> 7) & 0x03)));
        props.push_back(grc::writeGByte(rating_dev & 0x7f));
    }
    std::vector<uint8_t> data;
    writeAttrString(data, account_ptr);
    writeAttrString(data, jsonGetString(json, "world"));
    data.push_back(grc::writeGByte((int)props.size()));
    data.insert(data.end(), props.begin(), props.end());
    std::vector<std::string> flags = jsonGetStringArray(json, "flags");
    data.push_back((uint8_t)(((flags.size() >> 7) & 0xff) + 32)); data.push_back((uint8_t)((flags.size() & 0x7f) + 32));
    for (const auto& flag : flags) writeAttrString(data, flag);
    std::vector<std::string> chests = jsonGetStringArray(json, "chests");
    data.push_back((uint8_t)(((chests.size() >> 7) & 0xff) + 32)); data.push_back((uint8_t)((chests.size() & 0x7f) + 32));
    for (const auto& chest : chests) writeAttrString(data, chest);
    std::vector<std::string> weapons = jsonGetStringArray(json, "weapons");
    data.push_back(grc::writeGByte((int)weapons.size()));
    for (const auto& weapon : weapons) writeAttrString(data, weapon);
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PLAYERPROPSSET2, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

static int sendPlayerAccountPacket(RCConnection* conn, int packet_id, const char* account_ptr, const char* account_text_ptr) {
    if (!conn || !account_text_ptr) return 0;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::map<std::string, std::string> values = parseKeyValueLines(account_text_ptr);
    std::string account = values.count("account") ? values["account"] : (account_ptr ? account_ptr : "");
    if (account.empty()) return 0;
    int admin_level = std::atoi(values["admin_level"].c_str());
    if (admin_level > 0xdf) admin_level = 0xdf;
    if (admin_level < 0) admin_level = 0;
    std::vector<uint8_t> data;
    writeRcLenString(data, account);
    writeRcLenString(data, values["password"]);
    writeRcLenString(data, values["email"]);
    data.push_back((uint8_t)((truthyText(values["banned"]) ? 1 : 0) + 0x20));
    data.push_back((uint8_t)((truthyText(values["guest"]) ? 1 : 0) + 0x20));
    data.push_back((uint8_t)(admin_level + 0x20));
    writeRcLenString(data, values["admin_worlds"].empty() ? "all" : values["admin_worlds"]);
    writeRcLenString(data, values["ban_reason"]);
    std::vector<uint8_t> packet = conn->protocol.sendPacket(packet_id, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

int rc_set_player_account(RCHandle handle, const char* account_ptr, const char* account_text_ptr) {
    if (!handle || !account_ptr || !account_text_ptr) return 0;
    RCConnection* conn = (RCConnection*)handle;
    return sendPlayerAccountPacket(conn, PLI_RC_ACCOUNTSET, account_ptr, account_text_ptr);
}

int rc_add_player_account(RCHandle handle, const char* account_text_ptr) {
    if (!handle || !account_text_ptr) return 0;
    RCConnection* conn = (RCConnection*)handle;
    return sendPlayerAccountPacket(conn, PLI_RC_ACCOUNTADD, nullptr, account_text_ptr);
}

int rc_set_player_profile(RCHandle handle, const char* account_ptr, const char* profile_text_ptr) {
    if (!handle || !account_ptr || !profile_text_ptr) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::string account = account_ptr;
    std::vector<std::string> fields(11, "");
    std::map<std::string, int> labels = {{"Real Name", 1}, {"Age", 2}, {"Sex", 3}, {"Country", 4}, {"Messenger", 5}, {"E-Mail", 6}, {"Email", 6}, {"Homepage", 7}, {"Fav. Hangout", 8}, {"Favourite Quote", 9}, {"Favorite Quote", 9}, {"Online Time", 10}};
    std::stringstream stream(profile_text_ptr);
    std::string line;
    int plain_index = 0;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (trimText(line).empty() || startsWithText(line, "Profile for ")) continue;
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string label = trimText(line.substr(0, colon));
            if (labels.count(label)) fields[labels[label]] = trimText(line.substr(colon + 1));
        } else if (plain_index < 11) {
            fields[plain_index++] = line;
        }
    }
    std::vector<uint8_t> data;
    writeAttrString(data, account);
    for (int i = 1; i < 11; ++i) writeAttrString(data, fields[i]);
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_PROFILESET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

int rc_send_mass_pm(RCHandle handle, const int* player_ids, int count, const char* message) {
    if (!handle || !player_ids || count <= 0 || !message) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    if (count > 0x6fff) count = 0x6fff;
    std::vector<uint8_t> data;
    data.push_back((uint8_t)(((count >> 7) & 0xff) + 32));
    data.push_back((uint8_t)((count & 0x7f) + 32));
    for (int i = 0; i < count; ++i) grc::writeGShort(data, player_ids[i]);
    std::string tokenized = grc::gtokenizeString(message);
    data.insert(data.end(), tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_PRIVATEMESSAGE, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

char* rc_format_player_rights_text(int rights_value, const char* ip_range, const char* folder_access) {
    const auto& rights_names = rightsNames();
    std::ostringstream text;
    text << "IP Range: " << (ip_range ? ip_range : "") << "\n\n";
    text << "# Rights (set to true/false):\n";
    for (size_t i = 0; i < rights_names.size(); ++i) {
        if (rights_names[i].empty()) continue;
        text << rights_names[i] << ": " << (((rights_value & (1 << i)) != 0) ? "true" : "false") << "\n";
    }
    text << "\nFolder Access:\n" << (folder_access ? folder_access : "") << "\n";
    return grcStrdup(text.str().c_str());
}

char* rc_format_player_account_text(const char* account_data) {
    std::map<std::string, std::string> values;
    std::stringstream stream(account_data ? account_data : "");
    std::string line;
    while (std::getline(stream, line)) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) values[line.substr(0, pos)] = line.substr(pos + 1);
    }
    std::ostringstream text;
    text << "Account name: " << values["account"] << "\n";
    text << "Password:\n";
    text << "E-mail address: " << values["email"] << "\n";
    text << "Admin level: " << values["admin_level"] << "\n";
    text << "Admin worlds: " << values["admin_worlds"] << "\n";
    text << "Banned: " << (values["banned"] == "1" || values["banned"] == "true" ? "true" : "false") << "\n";
    text << "Guest: " << (values["guest"] == "1" || values["guest"] == "true" ? "true" : "false") << "\n";
    text << "Ban Time: Wed Dec 31 18:00:00 1969\n";
    text << "Ban-Reason / Comments: " << values["ban_reason"] << "\n";
    return grcStrdup(text.str().c_str());
}

char* rc_format_player_attributes_text(const char* properties_json) {
    std::string json = properties_json ? properties_json : "{}";
    std::vector<int> colors = jsonGetIntArray(json, "colors");
    while (colors.size() < 5) colors.push_back(0);
    int status = (int)jsonGetNumber(json, "18", 0);

    std::ostringstream text;
    text << "[Stats]\n";
    text << "Account: " << jsonGetString(json, "account") << "\n";
    text << "Last IP: " << jsonGetString(json, "last_ip") << "\n";
    text << "Kills: " << (int)jsonGetNumber(json, "27", 0) << "\n";
    text << "Deaths: " << (int)jsonGetNumber(json, "28", 0) << "\n";
    text << "Online Seconds: " << (int)jsonGetNumber(json, "29", 0) << "\n";
    text << "Rating: " << (int)jsonGetNumber(json, "rating", 0) << "\n";
    text << "Rating Deviation: " << (int)jsonGetNumber(json, "rating_dev", 0) << "\n\n";

    text << "[Look]\n";
    text << "Head Image: " << jsonGetString(json, "head_image", "head0.gif") << "\n";
    text << "Body Image: " << jsonGetString(json, "body_image") << "\n";
    text << "Animation: " << jsonGetString(json, "10") << "\n";
    text << "Skin Color: " << colorName(colors[0]) << "\n";
    text << "Coat Color: " << colorName(colors[1]) << "\n";
    text << "Sleeves Color: " << colorName(colors[2]) << "\n";
    text << "Shoes Color: " << colorName(colors[3]) << "\n";
    text << "Belt Color: " << colorName(colors[4]) << "\n\n";

    text << "[Basic Attributes]\n";
    text << "Level: " << jsonGetString(json, "20") << "\n";
    text << "X: " << (int)(jsonGetNumber(json, "5", 0) / 2.0) << "\n";
    text << "Y: " << (int)(jsonGetNumber(json, "6", 0) / 2.0) << "\n";
    text << "Hearts: " << (int)jsonGetNumber(json, "1", 0) << "\n";
    text << "Full Hearts: " << jsonGetNumber(json, "2", 0) << "\n";
    text << "MP: " << (int)jsonGetNumber(json, "27", 0) << "\n";
    text << "Gralats: " << (int)jsonGetNumber(json, "30", 0) << "\n";
    text << "Glove: " << (int)jsonGetNumber(json, "17", 0) << "\n";
    text << "Bombs: " << (int)jsonGetNumber(json, "19", 0) << "\n";
    text << "Arrows: " << (int)jsonGetNumber(json, "4", 0) << "\n";
    text << "Sword Power: " << jsonGetNumber(json, "sword_power", 0) << "\n";
    text << "Sword Image: " << jsonGetString(json, "sword_image") << "\n";
    text << "Shield Power: " << jsonGetNumber(json, "shield_power", 0) << "\n";
    text << "Shield Image: " << jsonGetString(json, "shield_image") << "\n";
    text << "Male: " << ((status & 4) ? "true" : "false") << "\n";
    text << "Weapons Enabled: " << ((status & 16) ? "true" : "false") << "\n";
    text << "Spin Attack: " << ((status & 64) ? "true" : "false") << "\n\n";

    text << "[Chests]\n";
    for (const auto& chest : jsonGetStringArray(json, "chests")) text << chest << "\n";
    text << "\n[Weapons]\n";
    for (const auto& weapon : jsonGetStringArray(json, "weapons")) text << weapon << "\n";
    text << "\n[Script Flags]\n";
    for (const auto& flag : jsonGetStringArray(json, "flags")) text << flag << "\n";
    return grcStrdup(text.str().c_str());
}

char* rc_parse_player_rights_text(const char* text_ptr) {
    if (!text_ptr) return nullptr;
    std::stringstream stream(text_ptr);
    std::string line;
    std::string ip_range;
    std::vector<std::string> folder_access;
    int rights_value = 0;
    bool in_folder_section = false;
    const auto& names = rightsNames();

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (startsWithText(line, "IP Range:")) {
            ip_range = trimText(line.substr(strlen("IP Range:")));
            in_folder_section = false;
            continue;
        }
        if (startsWithText(line, "Folder Access:")) {
            std::string first = trimText(line.substr(strlen("Folder Access:")));
            if (!first.empty()) folder_access.push_back(first);
            in_folder_section = true;
            continue;
        }
        if (startsWithText(line, "#")) {
            in_folder_section = false;
            continue;
        }
        if (in_folder_section) {
            std::string folder = trimText(line);
            if (!folder.empty()) folder_access.push_back(folder);
            continue;
        }

        for (size_t i = 0; i < names.size(); ++i) {
            if (names[i].empty()) continue;
            std::string prefix = names[i] + ":";
            if (startsWithText(line, prefix)) {
                if (truthyText(line.substr(prefix.size()))) rights_value |= (1 << i);
                break;
            }
        }
    }

    std::ostringstream out;
    out << "rights=" << rights_value << "\n";
    out << "ip=" << ip_range << "\n";
    out << "folders=" << joinLines(folder_access);
    return grcStrdup(out.str().c_str());
}

char* rc_parse_player_account_text(const char* text_ptr) {
    if (!text_ptr) return nullptr;
    std::stringstream stream(text_ptr);
    std::string line;
    std::map<std::string, std::string> values;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        line = trimText(line);
        if (line.empty()) continue;
        if (startsWithText(line, "old email:")) {
            values["old_email"] = trimText(line.substr(strlen("old email:")));
            continue;
        }
        if (startsWithText(line, "-") && line.find(',') != std::string::npos) {
            size_t comma = line.find(',');
            values["changed_by"] = trimText(line.substr(1, comma - 1));
            values["change_date"] = trimText(line.substr(comma + 1));
            continue;
        }
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string label = trimText(line.substr(0, colon));
        std::string value = trimText(line.substr(colon + 1));
        if (label == "Account name") values["account"] = value;
        else if (label == "Password") values["password"] = value;
        else if (label == "E-mail address") values["email"] = value;
        else if (label == "Admin level") values["admin_level"] = value;
        else if (label == "Admin worlds") values["admin_worlds"] = value;
        else if (label == "Banned") values["banned"] = truthyText(value) ? "1" : "0";
        else if (label == "Guest") values["guest"] = truthyText(value) ? "1" : "0";
        else if (label == "Ban Time") values["ban_time_text"] = value;
        else if (label == "Ban-Reason / Comments") values["ban_reason"] = value;
    }

    std::ostringstream out;
    for (const auto& item : values) out << item.first << "=" << item.second << "\n";
    return grcStrdup(out.str().c_str());
}

char* rc_parse_player_attributes_text(const char* text_ptr) {
    if (!text_ptr) return nullptr;
    std::stringstream stream(text_ptr);
    std::string line;
    std::string section;
    std::map<std::string, std::string> strings;
    std::map<std::string, double> numbers;
    std::vector<int> colors(5, 0);
    int status_bits = 0;
    std::vector<std::string> chests;
    std::vector<std::string> weapons;
    std::vector<std::string> flags;

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string trimmed = trimText(line);
        if (trimmed.empty()) continue;
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            section = trimmed.substr(1, trimmed.size() - 2);
            continue;
        }
        size_t colon = trimmed.find(':');
        if (colon != std::string::npos) {
            std::string label = trimText(trimmed.substr(0, colon));
            std::string value = trimText(trimmed.substr(colon + 1));
            if (label == "Account") strings["account"] = value;
            else if (label == "Last IP") strings["last_ip"] = value;
            else if (label == "Kills") numbers["27"] = std::atof(value.c_str());
            else if (label == "Deaths") numbers["28"] = std::atof(value.c_str());
            else if (label == "Online Seconds") numbers["29"] = std::atof(value.c_str());
            else if (label == "Rating") numbers["rating"] = std::atof(value.c_str());
            else if (label == "Rating Deviation") numbers["rating_dev"] = std::atof(value.c_str());
            else if (label == "Head Image") strings["head_image"] = value;
            else if (label == "Body Image") strings["body_image"] = value;
            else if (label == "Animation") strings["10"] = value;
            else if (label == "Skin Color") colors[0] = colorIndexFromText(value);
            else if (label == "Coat Color") colors[1] = colorIndexFromText(value);
            else if (label == "Sleeves Color") colors[2] = colorIndexFromText(value);
            else if (label == "Shoes Color") colors[3] = colorIndexFromText(value);
            else if (label == "Belt Color") colors[4] = colorIndexFromText(value);
            else if (label == "Level") strings["20"] = value;
            else if (label == "X") numbers["5"] = std::atof(value.c_str());
            else if (label == "Y") numbers["6"] = std::atof(value.c_str());
            else if (label == "Hearts") numbers["1"] = std::atof(value.c_str());
            else if (label == "Full Hearts") numbers["2"] = std::atof(value.c_str()) * 2.0;
            else if (label == "MP") numbers["27"] = std::atof(value.c_str());
            else if (label == "Gralats") numbers["30"] = std::atof(value.c_str());
            else if (label == "Glove") numbers["17"] = std::atof(value.c_str());
            else if (label == "Bombs") numbers["19"] = std::atof(value.c_str());
            else if (label == "Arrows") numbers["4"] = std::atof(value.c_str());
            else if (label == "Sword Power") strings["sword_power"] = value;
            else if (label == "Sword Image") strings["sword_image"] = value;
            else if (label == "Shield Power") strings["shield_power"] = value;
            else if (label == "Shield Image") strings["shield_image"] = value;
            else if ((label == "Male" || label == "Paused" || label == "Hidden" || label == "Dead" ||
                      label == "Weapons Enabled" || label == "Weapons allowed" || label == "Hide sword" ||
                      label == "Spin Attack" || label == "Has spin attack") && truthyText(value)) {
                if (label == "Paused") status_bits |= 1;
                else if (label == "Hidden") status_bits |= 2;
                else if (label == "Male") status_bits |= 4;
                else if (label == "Dead") status_bits |= 8;
                else if (label == "Weapons Enabled" || label == "Weapons allowed") status_bits |= 16;
                else if (label == "Hide sword") status_bits |= 32;
                else if (label == "Spin Attack" || label == "Has spin attack") status_bits |= 64;
            }
            continue;
        }
        if (section == "Chests") chests.push_back(trimmed);
        else if (section == "Weapons") weapons.push_back(trimmed);
        else if (section == "Script Flags") flags.push_back(trimmed);
    }

    std::ostringstream json;
    bool first = true;
    for (const auto& item : strings) jsonAddString(json, first, item.first, item.second);
    for (const auto& item : numbers) jsonAddNumber(json, first, item.first, item.second);
    jsonAddIntArray(json, first, "colors", colors);
    jsonAddNumber(json, first, "18", status_bits);
    jsonAddStringArray(json, first, "chests", chests);
    jsonAddStringArray(json, first, "weapons", weapons);
    jsonAddStringArray(json, first, "flags", flags);
    return grcStrdup(("{" + json.str() + "}").c_str());
}

int rc_is_new_protocol(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    return conn->is_new_protocol ? 1 : 0;
}

void rc_set_new_protocol(RCHandle handle, int enabled) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->is_new_protocol = (enabled != 0);
}

int rc_request_local_npcs(RCHandle handle, const char* level) {
    if (!handle || !level) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->nc_connected || !conn->nc_authenticated || conn->nc_socket == INVALID_SOCKET) return 0;
    {
        std::lock_guard<std::mutex> lock(conn->cache_mutex);
        conn->pending_local_npcs_level = level;
    }
    std::vector<uint8_t> data(level, level + strlen(level));
    std::vector<uint8_t> packet = conn->nc_protocol.sendPacket(PLI_NC_LOCALNPCSGET, data);
    return grc::sendAll(conn->nc_socket, packet.data(), packet.size()) ? 1 : 0;
}

int rc_send_irc_text(RCHandle handle, const char* command, const char* param1, const char* param2, const char* param3) {
    if (!handle || !command) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::string text = protocolTextNamespace() + "\nirc\n";
    text += command;
    if (param1) { text += "\n"; text += param1; }
    if (param2) { text += "\n"; text += param2; }
    if (param3) { text += "\n"; text += param3; }
    std::string tokenized = grc::gtokenizeString(text);
    std::vector<uint8_t> data(tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_SENDTEXT, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

int rc_irc_login(RCHandle handle) {
    return rc_send_irc_text(handle, "login", "-", nullptr, nullptr);
}

int rc_irc_join(RCHandle handle, const char* channel) {
    return rc_send_irc_text(handle, "join", channel, nullptr, nullptr);
}

int rc_irc_part(RCHandle handle, const char* channel) {
    return rc_send_irc_text(handle, "part", channel, nullptr, nullptr);
}

static int sendListerText(RCConnection* conn, const std::string& command, const std::string& value, int packet_id) {
    if (!conn || !conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::string text = protocolTextNamespace() + "\nlister\n" + command;
    if (!value.empty()) {
        text += "\n";
        text += value;
    }
    std::string tokenized = grc::gtokenizeString(text);
    std::vector<uint8_t> data(tokenized.begin(), tokenized.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(packet_id, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

int rc_request_player_ban(RCHandle handle, const char* account, int player_id) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    conn->pending_ban_account = account;
    conn->pending_ban_player_id = player_id;
    if (conn->is_new_protocol) {
        if (player_id >= 0) {
            return sendListerText(conn, "getbanbyid", std::to_string(player_id), PLI_SENDTEXT);
        }
        return sendListerText(conn, "getban", account, PLI_SENDTEXT);
    }
    std::vector<uint8_t> data(account, account + strlen(account));
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PLAYERBANGET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

int rc_request_player_ban_by_account(RCHandle handle, const char* account) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    conn->pending_ban_account = account;
    conn->pending_ban_player_id = -1;
    return sendListerText(conn, "getban", account, PLI_SENDTEXT);
}

int rc_request_ban_types(RCHandle handle) {
    if (!handle) return 0;
    RCConnection* conn = (RCConnection*)handle;
    return sendListerText(conn, "bantypes", "", PLI_REQUESTTEXT);
}

int rc_request_ban_history(RCHandle handle, const char* account) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    return sendListerText(conn, "getbanhistory", account, PLI_SENDTEXT);
}

int rc_request_staff_activity(RCHandle handle, const char* account) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    return sendListerText(conn, "getstaffactivity", account, PLI_SENDTEXT);
}

int rc_set_ban(RCHandle handle, const char* target, const char* world, int banned, const char* ban_type, const char* release_time, const char* reason) {
    if (!handle || !target || !world) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::string data = protocolTextNamespace() + ",lister,setban,";
    data += target;
    data += ",world=";
    data += world;
    data += ",banned=";
    data += banned ? "1" : "0";
    data += ",bantype=";
    if (ban_type) data += ban_type;
    if (release_time && release_time[0]) {
        data += ",releasetime=";
        data += release_time;
    }
    data += ",reason=";
    if (reason) data += reason;
    std::vector<uint8_t> payload(data.begin(), data.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_SENDTEXT, payload);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

int rc_set_legacy_player_ban(RCHandle handle, const char* account, int banned, const char* reason) {
    if (!handle || !account) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data;
    size_t account_len = strlen(account);
    if (account_len > 223) return 0;
    data.push_back(grc::writeGByte((int)account_len));
    data.insert(data.end(), account, account + account_len);
    data.push_back(grc::writeGByte(banned ? 1 : 0));
    std::string reason_text = reason ? reason : "";
    if (reason_text.size() > 223) reason_text = reason_text.substr(0, 223);
    data.push_back(grc::writeGByte((int)reason_text.size()));
    data.insert(data.end(), reason_text.begin(), reason_text.end());
    std::vector<uint8_t> packet = conn->protocol.sendPacket(PLI_RC_PLAYERBANSET, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}

int rc_send_raw_packet(RCHandle handle, int packet_id, const char* data_ptr, int length) {
    if (!handle || !data_ptr || length < 0) return 0;
    RCConnection* conn = (RCConnection*)handle;
    if (!conn->authenticated || conn->game_socket == INVALID_SOCKET) return 0;
    std::vector<uint8_t> data(data_ptr, data_ptr + length);
    std::vector<uint8_t> packet = conn->protocol.sendPacket(packet_id, data);
    return grc::sendAll(conn->game_socket, packet.data(), packet.size()) ? 1 : 0;
}
void rc_disconnect(RCHandle handle) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    conn->running = false;
    if (conn->game_socket != INVALID_SOCKET) {
        closesocket(conn->game_socket);
        conn->game_socket = INVALID_SOCKET;
    }
    if (conn->nc_socket != INVALID_SOCKET) {
        closesocket(conn->nc_socket);
        conn->nc_socket = INVALID_SOCKET;
    }
    if (conn->recv_thread.joinable()) conn->recv_thread.join();
    if (conn->nc_recv_thread.joinable()) conn->nc_recv_thread.join();
    delete conn;
}
void rc_process_events(RCHandle handle) {
    if (!handle) return;
    RCConnection* conn = (RCConnection*)handle;
    std::queue<std::pair<std::string, std::function<void()>>> events;
    {
        std::lock_guard<std::mutex> lock(conn->event_mutex);
        events.swap(conn->event_queue);
    }
    while (!events.empty()) {
        try {
            events.front().second();
            void* probe = malloc(16);
            if (probe) free(probe);
        } catch (const std::exception& e) {
            conn->setError(std::string("Event callback error: ") + e.what());
        } catch (...) {
            conn->setError("Event callback error: unknown exception");
        }
        events.pop();
    }
}
