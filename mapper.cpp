/**
 * mapper - A localhost-only web application for analyzing gatherd connection data
 * 
 * This application ingests connection data files produced by gatherd, normalizes
 * the data, and provides a web interface to search for systems by hostname or IP
 * and view their connections.
 * 
 * Build: g++ -std=c++20 -O2 -pthread -o mapper mapper.cpp
 * Run:   ./mapper --port 8080
 * 
 * Security: Binds to 127.0.0.1 only by default. No authentication required.
 * 
 * Author: Generated for network connection analysis
 * License: Public Domain
 */

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <algorithm>
#include <memory>
#include <optional>
#include <variant>
#include <functional>
#include <regex>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <cctype>
#include <array>
#include <bitset>

// POSIX/Linux headers
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>

// ============================================================================
// Configuration Constants
// ============================================================================

constexpr const char* DEFAULT_BIND_ADDRESS = "127.0.0.1";
constexpr int DEFAULT_PORT = 8080;
constexpr size_t MAX_REQUEST_SIZE = 100 * 1024 * 1024;  // 100 MB max upload
constexpr size_t BUFFER_SIZE = 65536;
constexpr int BACKLOG = 10;

// ============================================================================
// Forward Declarations
// ============================================================================

class HttpServer;
class ConnectionGraph;
class ServiceMapper;
class CIDRMatcher;

// ============================================================================
// Utility Functions
// ============================================================================

namespace utils {

// Trim whitespace from both ends of a string
std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Convert string to lowercase
std::string toLower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

// URL decode
std::string urlDecode(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int val = 0;
            std::istringstream iss(s.substr(i + 1, 2));
            if (iss >> std::hex >> val) {
                result += static_cast<char>(val);
                i += 2;
                continue;
            }
        } else if (s[i] == '+') {
            result += ' ';
            continue;
        }
        result += s[i];
    }
    return result;
}

// HTML escape
std::string htmlEscape(const std::string& s) {
    std::string result;
    result.reserve(s.size() * 1.1);
    for (char c : s) {
        switch (c) {
            case '&': result += "&amp;"; break;
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '"': result += "&quot;"; break;
            case '\'': result += "&#39;"; break;
            default: result += c;
        }
    }
    return result;
}

// Split string by delimiter
std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> tokens;
    std::istringstream iss(s);
    std::string token;
    while (std::getline(iss, token, delim)) {
        tokens.push_back(token);
    }
    return tokens;
}

// Check if string starts with prefix
bool startsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

// Check if string ends with suffix
bool endsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() && 
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Parse query string into key-value pairs
std::map<std::string, std::string> parseQueryString(const std::string& query) {
    std::map<std::string, std::string> params;
    auto pairs = split(query, '&');
    for (const auto& pair : pairs) {
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string key = urlDecode(pair.substr(0, eq));
            std::string value = urlDecode(pair.substr(eq + 1));
            params[key] = value;
        } else {
            params[urlDecode(pair)] = "";
        }
    }
    return params;
}

} // namespace utils

// ============================================================================
// IPv4/IPv6 Address Handling
// ============================================================================

/**
 * Represents an IP address (IPv4 or IPv6) in a normalized form
 */
struct IPAddress {
    bool is_ipv6 = false;
    std::array<uint8_t, 16> bytes = {};  // IPv4 uses first 4 bytes
    std::string original;  // Original string representation
    
    IPAddress() = default;
    
    // Parse an IP address string
    static std::optional<IPAddress> parse(const std::string& s) {
        IPAddress addr;
        addr.original = s;
        
        std::string normalized = s;
        // Remove brackets from IPv6 addresses
        if (!normalized.empty() && normalized.front() == '[') {
            size_t end = normalized.find(']');
            if (end != std::string::npos) {
                normalized = normalized.substr(1, end - 1);
            }
        }
        
        // Try IPv4 first
        struct in_addr addr4;
        if (inet_pton(AF_INET, normalized.c_str(), &addr4) == 1) {
            addr.is_ipv6 = false;
            std::memcpy(addr.bytes.data(), &addr4.s_addr, 4);
            return addr;
        }
        
        // Try IPv6
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, normalized.c_str(), &addr6) == 1) {
            addr.is_ipv6 = true;
            std::memcpy(addr.bytes.data(), addr6.s6_addr, 16);
            return addr;
        }
        
        return std::nullopt;
    }
    
    // Convert back to string
    std::string toString() const {
        char buf[INET6_ADDRSTRLEN];
        if (is_ipv6) {
            struct in6_addr addr6;
            std::memcpy(addr6.s6_addr, bytes.data(), 16);
            inet_ntop(AF_INET6, &addr6, buf, sizeof(buf));
            return buf;
        } else {
            struct in_addr addr4;
            std::memcpy(&addr4.s_addr, bytes.data(), 4);
            inet_ntop(AF_INET, &addr4, buf, sizeof(buf));
            return buf;
        }
    }
    
    // Display-friendly string (bracketed for IPv6)
    std::string toDisplayString() const {
        if (is_ipv6) {
            return "[" + toString() + "]";
        }
        return toString();
    }
    
    bool operator==(const IPAddress& other) const {
        return is_ipv6 == other.is_ipv6 && bytes == other.bytes;
    }
    
    bool operator<(const IPAddress& other) const {
        if (is_ipv6 != other.is_ipv6) return is_ipv6 < other.is_ipv6;
        return bytes < other.bytes;
    }
};

// Hash function for IPAddress
struct IPAddressHash {
    size_t operator()(const IPAddress& addr) const {
        size_t h = addr.is_ipv6 ? 1 : 0;
        for (size_t i = 0; i < (addr.is_ipv6 ? 16 : 4); ++i) {
            h ^= std::hash<uint8_t>{}(addr.bytes[i]) + 0x9e3779b9 + (h << 6) + (h >> 2);
        }
        return h;
    }
};

// ============================================================================
// CIDR Matcher
// ============================================================================

/**
 * Represents a CIDR range and provides matching functionality
 */
struct CIDRRange {
    IPAddress network;
    int prefix_length = 0;
    
    // Check if an IP address is within this CIDR range
    bool contains(const IPAddress& addr) const {
        if (addr.is_ipv6 != network.is_ipv6) return false;
        
        int bytes_to_check = prefix_length / 8;
        int bits_remaining = prefix_length % 8;
        int total_bytes = network.is_ipv6 ? 16 : 4;
        
        // Check full bytes
        for (int i = 0; i < bytes_to_check && i < total_bytes; ++i) {
            if (addr.bytes[i] != network.bytes[i]) return false;
        }
        
        // Check partial byte
        if (bits_remaining > 0 && bytes_to_check < total_bytes) {
            uint8_t mask = 0xFF << (8 - bits_remaining);
            if ((addr.bytes[bytes_to_check] & mask) != (network.bytes[bytes_to_check] & mask)) {
                return false;
            }
        }
        
        return true;
    }
    
    // Parse a CIDR notation string
    static std::optional<CIDRRange> parse(const std::string& s) {
        std::string input = utils::trim(s);
        if (input.empty()) return std::nullopt;
        
        size_t slash = input.find('/');
        if (slash == std::string::npos) {
            // No prefix, assume single host
            auto addr = IPAddress::parse(input);
            if (!addr) return std::nullopt;
            CIDRRange range;
            range.network = *addr;
            range.prefix_length = addr->is_ipv6 ? 128 : 32;
            return range;
        }
        
        std::string ip_part = input.substr(0, slash);
        std::string prefix_part = input.substr(slash + 1);
        
        auto addr = IPAddress::parse(ip_part);
        if (!addr) return std::nullopt;
        
        int prefix;
        try {
            prefix = std::stoi(prefix_part);
        } catch (...) {
            return std::nullopt;
        }
        
        int max_prefix = addr->is_ipv6 ? 128 : 32;
        if (prefix < 0 || prefix > max_prefix) return std::nullopt;
        
        CIDRRange range;
        range.network = *addr;
        range.prefix_length = prefix;
        
        // Normalize network address (zero out host bits)
        int bytes_to_keep = prefix / 8;
        int bits_remaining = prefix % 8;
        int total_bytes = addr->is_ipv6 ? 16 : 4;
        
        if (bits_remaining > 0 && bytes_to_keep < total_bytes) {
            uint8_t mask = 0xFF << (8 - bits_remaining);
            range.network.bytes[bytes_to_keep] &= mask;
            bytes_to_keep++;
        }
        
        for (int i = bytes_to_keep; i < total_bytes; ++i) {
            range.network.bytes[i] = 0;
        }
        
        return range;
    }
    
    std::string toString() const {
        return network.toString() + "/" + std::to_string(prefix_length);
    }
};

/**
 * Manages multiple CIDR ranges and provides matching
 */
class CIDRMatcher {
public:
    std::vector<CIDRRange> ranges;
    
    void clear() { ranges.clear(); }
    
    // Parse multiple CIDR ranges from text (comma or newline separated)
    std::pair<int, std::vector<std::string>> parseRanges(const std::string& input) {
        ranges.clear();
        std::vector<std::string> errors;
        int parsed = 0;
        
        // Replace newlines with commas for uniform parsing
        std::string normalized = input;
        for (char& c : normalized) {
            if (c == '\n' || c == '\r') c = ',';
        }
        
        auto parts = utils::split(normalized, ',');
        for (const auto& part : parts) {
            std::string trimmed = utils::trim(part);
            if (trimmed.empty()) continue;
            
            auto range = CIDRRange::parse(trimmed);
            if (range) {
                ranges.push_back(*range);
                parsed++;
            } else {
                errors.push_back("Invalid CIDR: " + trimmed);
            }
        }
        
        return {parsed, errors};
    }
    
    // Check if an IP is within any of the configured ranges
    bool matches(const IPAddress& addr) const {
        if (ranges.empty()) return true;  // No ranges = match all
        for (const auto& range : ranges) {
            if (range.contains(addr)) return true;
        }
        return false;
    }
    
    bool empty() const { return ranges.empty(); }
};

// ============================================================================
// Service Mapper
// ============================================================================

/**
 * Maps port numbers to service names
 */
class ServiceMapper {
public:
    struct ServiceInfo {
        std::string name;
        std::string protocol;  // tcp, udp, or both
        std::string description;
    };
    
    ServiceMapper() {
        initBuiltinServices();
        loadEtcServices();
    }
    
    // Get service info for a port
    std::optional<ServiceInfo> lookup(int port, const std::string& protocol = "tcp") const {
        auto it = services_.find(port);
        if (it != services_.end()) {
            // Try to find protocol-specific entry
            for (const auto& svc : it->second) {
                if (svc.protocol == protocol || svc.protocol == "both") {
                    return svc;
                }
            }
            // Return first match
            if (!it->second.empty()) {
                return it->second.front();
            }
        }
        return std::nullopt;
    }
    
    // Get service name or "unknown"
    std::string getServiceName(int port, const std::string& protocol = "tcp") const {
        auto info = lookup(port, protocol);
        return info ? info->name : "unknown";
    }
    
    // Check if port is typically ephemeral
    static bool isEphemeralPort(int port) {
        // Linux default ephemeral range: 32768-60999
        // Windows/older: 49152-65535
        // Conservative: consider > 32767 as potentially ephemeral
        return port > 32767;
    }
    
    // Determine which port is likely the service port
    static int getServicePort(int local_port, int remote_port) {
        // Prefer well-known ports (< 1024)
        if (local_port < 1024 && remote_port >= 1024) return local_port;
        if (remote_port < 1024 && local_port >= 1024) return remote_port;
        
        // Prefer registered ports (1024-49151) over ephemeral
        if (local_port < 49152 && remote_port >= 49152) return local_port;
        if (remote_port < 49152 && local_port >= 49152) return remote_port;
        
        // Prefer lower port number
        return std::min(local_port, remote_port);
    }

private:
    std::unordered_map<int, std::vector<ServiceInfo>> services_;
    
    void initBuiltinServices() {
        // Well-known services
        addService(20, "ftp-data", "tcp", "FTP Data");
        addService(21, "ftp", "tcp", "FTP Control");
        addService(22, "ssh", "tcp", "Secure Shell");
        addService(23, "telnet", "tcp", "Telnet");
        addService(25, "smtp", "tcp", "Simple Mail Transfer");
        addService(53, "dns", "both", "Domain Name System");
        addService(67, "dhcp-server", "udp", "DHCP Server");
        addService(68, "dhcp-client", "udp", "DHCP Client");
        addService(69, "tftp", "udp", "Trivial File Transfer");
        addService(80, "http", "tcp", "HTTP Web Server");
        addService(88, "kerberos", "both", "Kerberos Authentication");
        addService(110, "pop3", "tcp", "Post Office Protocol v3");
        addService(111, "rpcbind", "both", "RPC Bind");
        addService(123, "ntp", "udp", "Network Time Protocol");
        addService(135, "msrpc", "tcp", "Microsoft RPC");
        addService(137, "netbios-ns", "udp", "NetBIOS Name Service");
        addService(138, "netbios-dgm", "udp", "NetBIOS Datagram");
        addService(139, "netbios-ssn", "tcp", "NetBIOS Session");
        addService(143, "imap", "tcp", "Internet Message Access Protocol");
        addService(161, "snmp", "udp", "Simple Network Management Protocol");
        addService(162, "snmp-trap", "udp", "SNMP Traps");
        addService(389, "ldap", "tcp", "Lightweight Directory Access Protocol");
        addService(443, "https", "tcp", "HTTP over TLS/SSL");
        addService(445, "microsoft-ds", "tcp", "Microsoft Directory Services (SMB)");
        addService(464, "kpasswd", "both", "Kerberos Password Change");
        addService(465, "smtps", "tcp", "SMTP over SSL");
        addService(514, "syslog", "udp", "System Logging");
        addService(515, "printer", "tcp", "Line Printer Daemon");
        addService(587, "submission", "tcp", "Mail Submission");
        addService(636, "ldaps", "tcp", "LDAP over SSL");
        addService(873, "rsync", "tcp", "rsync File Transfer");
        addService(993, "imaps", "tcp", "IMAP over SSL");
        addService(995, "pop3s", "tcp", "POP3 over SSL");
        
        // Database ports
        addService(1433, "ms-sql-s", "tcp", "Microsoft SQL Server");
        addService(1434, "ms-sql-m", "udp", "Microsoft SQL Server Monitor");
        addService(1521, "oracle", "tcp", "Oracle Database");
        addService(1830, "oracle-net8", "tcp", "Oracle Net8 Cman");
        addService(3306, "mysql", "tcp", "MySQL Database");
        addService(5432, "postgresql", "tcp", "PostgreSQL Database");
        addService(6379, "redis", "tcp", "Redis Key-Value Store");
        addService(27017, "mongodb", "tcp", "MongoDB Database");
        addService(9042, "cassandra", "tcp", "Apache Cassandra");
        addService(9200, "elasticsearch", "tcp", "Elasticsearch HTTP");
        addService(9300, "elasticsearch-transport", "tcp", "Elasticsearch Transport");
        
        // Remote access
        addService(3389, "ms-wbt-server", "tcp", "Microsoft RDP");
        addService(5900, "vnc", "tcp", "Virtual Network Computing");
        addService(5901, "vnc-1", "tcp", "VNC Display 1");
        
        // Web services
        addService(8080, "http-proxy", "tcp", "HTTP Proxy/Alt HTTP");
        addService(8443, "https-alt", "tcp", "Alternative HTTPS");
        addService(8888, "http-alt", "tcp", "Alternative HTTP");
        
        // Application servers
        addService(9000, "cslistener", "tcp", "CSListener/PHP-FPM");
        addService(9090, "websm", "tcp", "WebSM/Prometheus");
        
        // Message queues
        addService(5672, "amqp", "tcp", "AMQP (RabbitMQ)");
        addService(15672, "rabbitmq-mgmt", "tcp", "RabbitMQ Management");
        addService(9092, "kafka", "tcp", "Apache Kafka");
        addService(2181, "zookeeper", "tcp", "Apache ZooKeeper");
        
        // Container/orchestration
        addService(2375, "docker", "tcp", "Docker API (unencrypted)");
        addService(2376, "docker-s", "tcp", "Docker API (TLS)");
        addService(6443, "kubernetes-api", "tcp", "Kubernetes API Server");
        addService(10250, "kubelet", "tcp", "Kubernetes Kubelet API");
        
        // Monitoring
        addService(9100, "node-exporter", "tcp", "Prometheus Node Exporter");
        addService(9093, "alertmanager", "tcp", "Prometheus Alertmanager");
        addService(3000, "grafana", "tcp", "Grafana");
        
        // Other common
        addService(11211, "memcached", "tcp", "Memcached");
        addService(1194, "openvpn", "udp", "OpenVPN");
        addService(500, "isakmp", "udp", "ISAKMP/IKE");
        addService(4500, "nat-t-ike", "udp", "NAT-T IKE");
    }
    
    void addService(int port, const std::string& name, const std::string& protocol, 
                    const std::string& description) {
        services_[port].push_back({name, protocol, description});
    }
    
    void loadEtcServices() {
        std::ifstream file("/etc/services");
        if (!file.is_open()) return;
        
        std::string line;
        while (std::getline(file, line)) {
            // Skip comments and empty lines
            size_t comment = line.find('#');
            if (comment != std::string::npos) {
                line = line.substr(0, comment);
            }
            line = utils::trim(line);
            if (line.empty()) continue;
            
            // Parse: service_name port/protocol [aliases...]
            std::istringstream iss(line);
            std::string name, port_proto;
            if (!(iss >> name >> port_proto)) continue;
            
            size_t slash = port_proto.find('/');
            if (slash == std::string::npos) continue;
            
            std::string port_str = port_proto.substr(0, slash);
            std::string protocol = port_proto.substr(slash + 1);
            
            int port;
            try {
                port = std::stoi(port_str);
            } catch (...) {
                continue;
            }
            
            if (port < 0 || port > 65535) continue;
            
            // Only add if we don't already have a built-in entry
            bool exists = false;
            if (services_.count(port)) {
                for (const auto& svc : services_[port]) {
                    if (svc.name == name) {
                        exists = true;
                        break;
                    }
                }
            }
            
            if (!exists) {
                addService(port, name, protocol, "");
            }
        }
    }
};

// ============================================================================
// Connection Record
// ============================================================================

/**
 * Represents a single connection record from gatherd
 */
struct ConnectionRecord {
    std::string hostname;
    IPAddress local_ip;
    int local_port = 0;
    IPAddress remote_ip;
    int remote_port = 0;
    std::string direction;  // "Inbound" or "Outbound"
    std::string source_file;
    
    // Generate a unique key for deduplication
    std::string uniqueKey() const {
        std::ostringstream oss;
        oss << hostname << "|" << local_ip.toString() << "|" << local_port << "|"
            << remote_ip.toString() << "|" << remote_port << "|" << direction;
        return oss.str();
    }
    
    bool operator==(const ConnectionRecord& other) const {
        return uniqueKey() == other.uniqueKey();
    }
};

// ============================================================================
// Minimal JSON Parser
// ============================================================================

/**
 * Minimal JSON parser sufficient for gatherd JSON output
 * Parses arrays of objects with string/number values
 */
class JsonParser {
public:
    struct JsonValue;
    using JsonObject = std::map<std::string, JsonValue>;
    using JsonArray = std::vector<JsonValue>;
    
    struct JsonValue {
        enum Type { Null, Bool, Number, String, Array, Object };
        Type type = Null;
        bool bool_val = false;
        double num_val = 0;
        std::string str_val;
        JsonArray arr_val;
        JsonObject obj_val;
        
        bool isNull() const { return type == Null; }
        bool isBool() const { return type == Bool; }
        bool isNumber() const { return type == Number; }
        bool isString() const { return type == String; }
        bool isArray() const { return type == Array; }
        bool isObject() const { return type == Object; }
        
        int asInt() const { return static_cast<int>(num_val); }
        const std::string& asString() const { return str_val; }
    };
    
    std::optional<JsonValue> parse(const std::string& json) {
        pos_ = 0;
        json_ = &json;
        skipWhitespace();
        return parseValue();
    }
    
private:
    size_t pos_ = 0;
    const std::string* json_ = nullptr;
    
    char peek() const {
        return pos_ < json_->size() ? (*json_)[pos_] : '\0';
    }
    
    char get() {
        return pos_ < json_->size() ? (*json_)[pos_++] : '\0';
    }
    
    void skipWhitespace() {
        while (pos_ < json_->size() && std::isspace(static_cast<unsigned char>((*json_)[pos_]))) {
            pos_++;
        }
    }
    
    std::optional<JsonValue> parseValue() {
        skipWhitespace();
        char c = peek();
        
        if (c == '"') return parseString();
        if (c == '[') return parseArray();
        if (c == '{') return parseObject();
        if (c == 't' || c == 'f') return parseBool();
        if (c == 'n') return parseNull();
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parseNumber();
        
        return std::nullopt;
    }
    
    std::optional<JsonValue> parseString() {
        if (get() != '"') return std::nullopt;
        
        std::string result;
        while (true) {
            char c = get();
            if (c == '\0') return std::nullopt;
            if (c == '"') break;
            if (c == '\\') {
                c = get();
                switch (c) {
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/': result += '/'; break;
                    case 'b': result += '\b'; break;
                    case 'f': result += '\f'; break;
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    case 'u': {
                        // Unicode escape - simplified handling
                        std::string hex;
                        for (int i = 0; i < 4; ++i) {
                            char h = get();
                            if (!std::isxdigit(static_cast<unsigned char>(h))) return std::nullopt;
                            hex += h;
                        }
                        int code = std::stoi(hex, nullptr, 16);
                        if (code < 128) {
                            result += static_cast<char>(code);
                        } else {
                            // Basic UTF-8 encoding for BMP characters
                            if (code < 0x800) {
                                result += static_cast<char>(0xC0 | (code >> 6));
                                result += static_cast<char>(0x80 | (code & 0x3F));
                            } else {
                                result += static_cast<char>(0xE0 | (code >> 12));
                                result += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                                result += static_cast<char>(0x80 | (code & 0x3F));
                            }
                        }
                        break;
                    }
                    default: result += c;
                }
            } else {
                result += c;
            }
        }
        
        JsonValue val;
        val.type = JsonValue::String;
        val.str_val = result;
        return val;
    }
    
    std::optional<JsonValue> parseNumber() {
        size_t start = pos_;
        if (peek() == '-') pos_++;
        
        while (std::isdigit(static_cast<unsigned char>(peek()))) pos_++;
        
        if (peek() == '.') {
            pos_++;
            while (std::isdigit(static_cast<unsigned char>(peek()))) pos_++;
        }
        
        if (peek() == 'e' || peek() == 'E') {
            pos_++;
            if (peek() == '+' || peek() == '-') pos_++;
            while (std::isdigit(static_cast<unsigned char>(peek()))) pos_++;
        }
        
        std::string num_str = json_->substr(start, pos_ - start);
        JsonValue val;
        val.type = JsonValue::Number;
        try {
            val.num_val = std::stod(num_str);
        } catch (...) {
            return std::nullopt;
        }
        return val;
    }
    
    std::optional<JsonValue> parseBool() {
        if (json_->substr(pos_, 4) == "true") {
            pos_ += 4;
            JsonValue val;
            val.type = JsonValue::Bool;
            val.bool_val = true;
            return val;
        }
        if (json_->substr(pos_, 5) == "false") {
            pos_ += 5;
            JsonValue val;
            val.type = JsonValue::Bool;
            val.bool_val = false;
            return val;
        }
        return std::nullopt;
    }
    
    std::optional<JsonValue> parseNull() {
        if (json_->substr(pos_, 4) == "null") {
            pos_ += 4;
            JsonValue val;
            val.type = JsonValue::Null;
            return val;
        }
        return std::nullopt;
    }
    
    std::optional<JsonValue> parseArray() {
        if (get() != '[') return std::nullopt;
        
        JsonValue val;
        val.type = JsonValue::Array;
        
        skipWhitespace();
        if (peek() == ']') {
            pos_++;
            return val;
        }
        
        while (true) {
            auto elem = parseValue();
            if (!elem) return std::nullopt;
            val.arr_val.push_back(*elem);
            
            skipWhitespace();
            char c = get();
            if (c == ']') break;
            if (c != ',') return std::nullopt;
            skipWhitespace();
        }
        
        return val;
    }
    
    std::optional<JsonValue> parseObject() {
        if (get() != '{') return std::nullopt;
        
        JsonValue val;
        val.type = JsonValue::Object;
        
        skipWhitespace();
        if (peek() == '}') {
            pos_++;
            return val;
        }
        
        while (true) {
            skipWhitespace();
            auto key = parseString();
            if (!key || !key->isString()) return std::nullopt;
            
            skipWhitespace();
            if (get() != ':') return std::nullopt;
            
            auto value = parseValue();
            if (!value) return std::nullopt;
            
            val.obj_val[key->str_val] = *value;
            
            skipWhitespace();
            char c = get();
            if (c == '}') break;
            if (c != ',') return std::nullopt;
        }
        
        return val;
    }
};

// ============================================================================
// Gatherd Parser
// ============================================================================

/**
 * Parses gatherd output files (both JSON and colon-separated text formats)
 */
class GatherdParser {
public:
    struct ParseResult {
        std::vector<ConnectionRecord> records;
        int accepted = 0;
        int rejected = 0;
        std::vector<std::string> errors;
    };
    
    // Parse file content and auto-detect format
    ParseResult parse(const std::string& content, const std::string& source_file) {
        ParseResult result;
        
        std::string trimmed = utils::trim(content);
        if (trimmed.empty()) {
            result.errors.push_back("Empty file content");
            return result;
        }
        
        // Detect format by first non-whitespace character
        if (trimmed[0] == '[') {
            // JSON array format
            return parseJson(content, source_file);
        } else {
            // Colon-separated text format
            return parseText(content, source_file);
        }
    }
    
private:
    /**
     * Parse colon-separated text format
     * Format: hostname:local_ip:local_port:remote_ip:remote_port:direction
     * 
     * Special handling for IPv6: addresses may be bracketed like [2001:db8::1]
     * We cannot simply split on ':' because IPv6 contains colons
     */
    ParseResult parseText(const std::string& content, const std::string& source_file) {
        ParseResult result;
        std::istringstream iss(content);
        std::string line;
        int line_num = 0;
        
        while (std::getline(iss, line)) {
            line_num++;
            line = utils::trim(line);
            if (line.empty() || line[0] == '#') continue;
            
            auto record = parseTextLine(line, source_file);
            if (record) {
                result.records.push_back(*record);
                result.accepted++;
            } else {
                result.rejected++;
                if (result.errors.size() < 10) {
                    result.errors.push_back("Line " + std::to_string(line_num) + ": " + line);
                }
            }
        }
        
        return result;
    }
    
    /**
     * Parse a single text line with proper IPv6 handling
     * 
     * The format is: hostname:local_ip:local_port:remote_ip:remote_port:direction
     * IPv6 addresses are bracketed: [2001:db8::1]
     * 
     * Strategy: parse field by field, handling brackets specially
     */
    std::optional<ConnectionRecord> parseTextLine(const std::string& line, const std::string& source_file) {
        std::vector<std::string> fields;
        std::string current;
        bool in_brackets = false;
        
        for (size_t i = 0; i < line.size(); ++i) {
            char c = line[i];
            
            if (c == '[') {
                in_brackets = true;
                current += c;
            } else if (c == ']') {
                in_brackets = false;
                current += c;
            } else if (c == ':' && !in_brackets) {
                fields.push_back(current);
                current.clear();
            } else {
                current += c;
            }
        }
        fields.push_back(current);
        
        if (fields.size() != 6) return std::nullopt;
        
        ConnectionRecord record;
        record.source_file = source_file;
        
        // Field 0: hostname
        record.hostname = utils::trim(fields[0]);
        if (record.hostname.empty()) return std::nullopt;
        
        // Field 1: local_ip
        auto local_ip = IPAddress::parse(utils::trim(fields[1]));
        if (!local_ip) return std::nullopt;
        record.local_ip = *local_ip;
        
        // Field 2: local_port
        try {
            record.local_port = std::stoi(utils::trim(fields[2]));
            if (record.local_port < 0 || record.local_port > 65535) return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
        
        // Field 3: remote_ip
        auto remote_ip = IPAddress::parse(utils::trim(fields[3]));
        if (!remote_ip) return std::nullopt;
        record.remote_ip = *remote_ip;
        
        // Field 4: remote_port
        try {
            record.remote_port = std::stoi(utils::trim(fields[4]));
            if (record.remote_port < 0 || record.remote_port > 65535) return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
        
        // Field 5: direction
        record.direction = utils::trim(fields[5]);
        if (record.direction != "Inbound" && record.direction != "Outbound") {
            return std::nullopt;
        }
        
        return record;
    }
    
    // Parse JSON array format
    ParseResult parseJson(const std::string& content, const std::string& source_file) {
        ParseResult result;
        JsonParser parser;
        
        auto json = parser.parse(content);
        if (!json || !json->isArray()) {
            result.errors.push_back("Invalid JSON: expected array");
            return result;
        }
        
        int index = 0;
        for (const auto& elem : json->arr_val) {
            index++;
            if (!elem.isObject()) {
                result.rejected++;
                if (result.errors.size() < 10) {
                    result.errors.push_back("Element " + std::to_string(index) + ": not an object");
                }
                continue;
            }
            
            auto record = parseJsonObject(elem.obj_val, source_file);
            if (record) {
                result.records.push_back(*record);
                result.accepted++;
            } else {
                result.rejected++;
                if (result.errors.size() < 10) {
                    result.errors.push_back("Element " + std::to_string(index) + ": invalid record");
                }
            }
        }
        
        return result;
    }
    
    std::optional<ConnectionRecord> parseJsonObject(const JsonParser::JsonObject& obj, 
                                                     const std::string& source_file) {
        ConnectionRecord record;
        record.source_file = source_file;
        
        // Required fields
        auto it = obj.find("hostname");
        if (it == obj.end() || !it->second.isString()) return std::nullopt;
        record.hostname = it->second.str_val;
        
        it = obj.find("local_ip");
        if (it == obj.end() || !it->second.isString()) return std::nullopt;
        auto local_ip = IPAddress::parse(it->second.str_val);
        if (!local_ip) return std::nullopt;
        record.local_ip = *local_ip;
        
        it = obj.find("local_port");
        if (it == obj.end() || !it->second.isNumber()) return std::nullopt;
        record.local_port = it->second.asInt();
        if (record.local_port < 0 || record.local_port > 65535) return std::nullopt;
        
        it = obj.find("remote_ip");
        if (it == obj.end() || !it->second.isString()) return std::nullopt;
        auto remote_ip = IPAddress::parse(it->second.str_val);
        if (!remote_ip) return std::nullopt;
        record.remote_ip = *remote_ip;
        
        it = obj.find("remote_port");
        if (it == obj.end() || !it->second.isNumber()) return std::nullopt;
        record.remote_port = it->second.asInt();
        if (record.remote_port < 0 || record.remote_port > 65535) return std::nullopt;
        
        it = obj.find("direction");
        if (it == obj.end() || !it->second.isString()) return std::nullopt;
        record.direction = it->second.str_val;
        if (record.direction != "Inbound" && record.direction != "Outbound") {
            return std::nullopt;
        }
        
        return record;
    }
};

// ============================================================================
// Connection Graph
// ============================================================================

/**
 * Graph model representing network connections between systems
 */
class ConnectionGraph {
public:
    /**
     * Represents a network node (system)
     */
    struct Node {
        std::set<std::string> hostnames;
        std::set<IPAddress> ip_addresses;
        bool in_range = false;  // Whether any IP is within configured CIDR ranges
        std::string primary_id;  // Primary identifier (first hostname or IP)
        
        std::string getPrimaryHostname() const {
            return hostnames.empty() ? "" : *hostnames.begin();
        }
        
        std::string getPrimaryIP() const {
            return ip_addresses.empty() ? "" : ip_addresses.begin()->toString();
        }
        
        std::string getDisplayName() const {
            if (!hostnames.empty()) return *hostnames.begin();
            if (!ip_addresses.empty()) return ip_addresses.begin()->toDisplayString();
            return "unknown";
        }
    };
    
    /**
     * Represents a connection edge between two nodes
     */
    struct Edge {
        std::string source_id;
        std::string dest_id;
        int local_port = 0;
        int remote_port = 0;
        std::string direction;
        std::string service_name;
        int service_port = 0;
        std::string source_file;
    };
    
    // Clear all data
    void clear() {
        nodes_.clear();
        edges_.clear();
        ip_to_node_.clear();
        hostname_to_node_.clear();
        unique_records_.clear();
    }
    
    // Ingest records into the graph
    void ingest(const std::vector<ConnectionRecord>& records, 
                const CIDRMatcher& cidr_matcher,
                const ServiceMapper& service_mapper) {
        for (const auto& record : records) {
            // Deduplication
            std::string key = record.uniqueKey();
            if (unique_records_.count(key)) continue;
            unique_records_.insert(key);
            
            // Get or create local node
            std::string local_id = getOrCreateNode(record.hostname, record.local_ip, cidr_matcher);
            
            // Get or create remote node (no hostname known)
            std::string remote_id = getOrCreateNode("", record.remote_ip, cidr_matcher);
            
            // Create edge
            Edge edge;
            edge.source_id = local_id;
            edge.dest_id = remote_id;
            edge.local_port = record.local_port;
            edge.remote_port = record.remote_port;
            edge.direction = record.direction;
            edge.source_file = record.source_file;
            
            // Determine service
            edge.service_port = ServiceMapper::getServicePort(record.local_port, record.remote_port);
            edge.service_name = service_mapper.getServiceName(edge.service_port);
            
            edges_.push_back(edge);
        }
    }
    
    // Search for a node by hostname or IP
    std::vector<std::string> search(const std::string& query) const {
        std::vector<std::string> results;
        std::string lower_query = utils::toLower(utils::trim(query));
        
        if (lower_query.empty()) return results;
        
        // Try exact IP match first
        auto ip = IPAddress::parse(query);
        if (ip) {
            auto it = ip_to_node_.find(*ip);
            if (it != ip_to_node_.end()) {
                results.push_back(it->second);
                return results;
            }
        }
        
        // Try hostname match (case-insensitive)
        for (const auto& [hostname, node_id] : hostname_to_node_) {
            if (utils::toLower(hostname) == lower_query) {
                if (std::find(results.begin(), results.end(), node_id) == results.end()) {
                    results.push_back(node_id);
                }
            }
        }
        
        // If no exact match, try partial hostname match
        if (results.empty()) {
            for (const auto& [hostname, node_id] : hostname_to_node_) {
                if (utils::toLower(hostname).find(lower_query) != std::string::npos) {
                    if (std::find(results.begin(), results.end(), node_id) == results.end()) {
                        results.push_back(node_id);
                    }
                }
            }
        }
        
        return results;
    }
    
    // Get node by ID
    const Node* getNode(const std::string& id) const {
        auto it = nodes_.find(id);
        return it != nodes_.end() ? &it->second : nullptr;
    }
    
    // Get all edges connected to a node
    std::vector<const Edge*> getEdges(const std::string& node_id) const {
        std::vector<const Edge*> result;
        for (const auto& edge : edges_) {
            if (edge.source_id == node_id || edge.dest_id == node_id) {
                result.push_back(&edge);
            }
        }
        return result;
    }
    
    // Get suggestions for type-ahead
    std::vector<std::string> getSuggestions(const std::string& prefix, int limit = 10) const {
        std::vector<std::string> results;
        std::string lower_prefix = utils::toLower(utils::trim(prefix));
        
        if (lower_prefix.empty()) return results;
        
        // Add matching hostnames
        for (const auto& [hostname, _] : hostname_to_node_) {
            if (utils::toLower(hostname).find(lower_prefix) == 0) {
                results.push_back(hostname);
                if (results.size() >= static_cast<size_t>(limit)) break;
            }
        }
        
        // Add matching IPs
        if (results.size() < static_cast<size_t>(limit)) {
            for (const auto& [ip, _] : ip_to_node_) {
                std::string ip_str = ip.toString();
                if (ip_str.find(lower_prefix) == 0) {
                    results.push_back(ip_str);
                    if (results.size() >= static_cast<size_t>(limit)) break;
                }
            }
        }
        
        return results;
    }
    
    // Statistics
    size_t nodeCount() const { return nodes_.size(); }
    size_t edgeCount() const { return edges_.size(); }
    size_t uniqueRecordCount() const { return unique_records_.size(); }
    
    // Get all nodes (for filtering by in_range)
    const std::map<std::string, Node>& getNodes() const { return nodes_; }

private:
    std::map<std::string, Node> nodes_;
    std::vector<Edge> edges_;
    std::unordered_map<IPAddress, std::string, IPAddressHash> ip_to_node_;
    std::map<std::string, std::string> hostname_to_node_;
    std::unordered_set<std::string> unique_records_;
    int next_node_id_ = 1;
    
    std::string getOrCreateNode(const std::string& hostname, const IPAddress& ip, 
                                 const CIDRMatcher& cidr_matcher) {
        // Check if IP already has a node
        auto it = ip_to_node_.find(ip);
        if (it != ip_to_node_.end()) {
            // Add hostname if provided and not already known
            if (!hostname.empty()) {
                nodes_[it->second].hostnames.insert(hostname);
                hostname_to_node_[hostname] = it->second;
            }
            return it->second;
        }
        
        // Check if hostname already has a node
        if (!hostname.empty()) {
            auto hit = hostname_to_node_.find(hostname);
            if (hit != hostname_to_node_.end()) {
                // Add IP to existing node
                nodes_[hit->second].ip_addresses.insert(ip);
                ip_to_node_[ip] = hit->second;
                // Update in_range if this IP is in range
                if (cidr_matcher.matches(ip)) {
                    nodes_[hit->second].in_range = true;
                }
                return hit->second;
            }
        }
        
        // Create new node
        std::string node_id = "node_" + std::to_string(next_node_id_++);
        Node node;
        if (!hostname.empty()) {
            node.hostnames.insert(hostname);
        }
        node.ip_addresses.insert(ip);
        node.in_range = cidr_matcher.matches(ip);
        node.primary_id = !hostname.empty() ? hostname : ip.toString();
        
        nodes_[node_id] = node;
        ip_to_node_[ip] = node_id;
        if (!hostname.empty()) {
            hostname_to_node_[hostname] = node_id;
        }
        
        return node_id;
    }
};

// ============================================================================
// HTML Renderer
// ============================================================================

/**
 * Generates HTML for the web UI
 */
class HtmlRenderer {
public:
    HtmlRenderer(const ServiceMapper& service_mapper) : service_mapper_(service_mapper) {}
    
    // Render main page
    std::string renderMainPage(const ConnectionGraph& graph, const CIDRMatcher& cidr_matcher,
                                const std::vector<std::string>& ingested_files,
                                int total_accepted, int total_rejected) {
        std::ostringstream html;
        
        html << R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mapper - Network Connection Analyzer</title>
    <style>
        :root {
            --bg: #0f1419;
            --bg-secondary: #1a1f2e;
            --bg-tertiary: #242d3d;
            --text: #e6e8eb;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --success: #3fb950;
            --warning: #d29922;
            --error: #f85149;
            --border: #30363d;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        header {
            text-align: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }
        
        h1 { 
            font-size: 2rem; 
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            color: var(--text-secondary);
            font-size: 0.95rem;
        }
        
        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        
        .section-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .section-title::before {
            content: '';
            width: 4px;
            height: 1.2rem;
            background: var(--accent);
            border-radius: 2px;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        input[type="text"], input[type="file"], textarea {
            width: 100%;
            padding: 0.75rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text);
            font-size: 0.95rem;
            margin-bottom: 1rem;
        }
        
        input[type="text"]:focus, textarea:focus {
            outline: none;
            border-color: var(--accent);
        }
        
        textarea {
            min-height: 80px;
            resize: vertical;
            font-family: monospace;
        }
        
        button {
            background: var(--accent);
            color: #fff;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            font-size: 0.95rem;
            font-weight: 500;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        
        button:hover { opacity: 0.9; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        
        .btn-secondary {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }
        
        .stat {
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 6px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--accent);
        }
        
        .stat-label {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        
        .file-list {
            list-style: none;
            margin: 0.5rem 0;
        }
        
        .file-list li {
            padding: 0.5rem;
            background: var(--bg-tertiary);
            border-radius: 4px;
            margin-bottom: 0.25rem;
            font-family: monospace;
            font-size: 0.9rem;
        }
        
        .badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .badge-success { background: rgba(63, 185, 80, 0.2); color: var(--success); }
        .badge-warning { background: rgba(210, 153, 34, 0.2); color: var(--warning); }
        .badge-error { background: rgba(248, 81, 73, 0.2); color: var(--error); }
        .badge-info { background: rgba(88, 166, 255, 0.2); color: var(--accent); }
        
        .cidr-list {
            font-family: monospace;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }
        
        #results { display: none; }
        
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .node-card {
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .node-name {
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .node-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }
        
        .connections-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        
        .connections-table th,
        .connections-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        .connections-table th {
            background: var(--bg-secondary);
            font-weight: 600;
            color: var(--text-secondary);
        }
        
        .connections-table tr:hover {
            background: var(--bg-secondary);
        }
        
        .port { font-family: monospace; }
        
        .service {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            background: rgba(88, 166, 255, 0.1);
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
        }
        
        .in-range { color: var(--success); }
        .out-range { color: var(--warning); }
        
        .topology {
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            min-height: 300px;
            position: relative;
        }
        
        .topology svg {
            width: 100%;
            height: 300px;
        }
        
        .suggestions {
            position: absolute;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 6px;
            max-height: 200px;
            overflow-y: auto;
            z-index: 100;
            display: none;
        }
        
        .suggestions.active { display: block; }
        
        .suggestion {
            padding: 0.5rem 0.75rem;
            cursor: pointer;
            font-family: monospace;
        }
        
        .suggestion:hover {
            background: var(--bg-secondary);
        }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
        }
        
        .error-msg {
            background: rgba(248, 81, 73, 0.1);
            border: 1px solid var(--error);
            color: var(--error);
            padding: 1rem;
            border-radius: 6px;
            margin: 1rem 0;
        }
        
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .stats { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Mapper</h1>
            <p class="subtitle">Network Connection Analyzer for gatherd output</p>
        </header>
        
        <div class="section" id="input-section">
            <h2 class="section-title">Input</h2>
            <form id="ingest-form" enctype="multipart/form-data">
                <label for="files">Select gatherd output files</label>
                <input type="file" id="files" name="files" multiple accept=".txt,.json,.log">
                
                <label for="cidr">IP ranges to consider (CIDR notation, one per line)</label>
                <textarea id="cidr" name="cidr" placeholder="10.0.0.0/8&#10;192.168.0.0/16&#10;2001:db8::/32">)";
        
        // Pre-fill CIDR ranges if already configured
        if (!cidr_matcher.empty()) {
            for (const auto& range : cidr_matcher.ranges) {
                html << utils::htmlEscape(range.toString()) << "\n";
            }
        }
        
        html << R"(</textarea>
                
                <button type="submit" id="ingest-btn">Ingest & Analyze</button>
            </form>
        </div>
        
        <div class="section" id="status-section">
            <h2 class="section-title">Status</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value" id="stat-files">)" << ingested_files.size() << R"(</div>
                    <div class="stat-label">Files Ingested</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="stat-accepted">)" << total_accepted << R"(</div>
                    <div class="stat-label">Records Accepted</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="stat-rejected">)" << total_rejected << R"(</div>
                    <div class="stat-label">Records Rejected</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="stat-unique">)" << graph.uniqueRecordCount() << R"(</div>
                    <div class="stat-label">Unique Connections</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="stat-nodes">)" << graph.nodeCount() << R"(</div>
                    <div class="stat-label">Systems</div>
                </div>
            </div>)";
        
        if (!ingested_files.empty()) {
            html << R"(<label>Ingested Files</label><ul class="file-list">)";
            for (const auto& file : ingested_files) {
                html << "<li>" << utils::htmlEscape(file) << "</li>";
            }
            html << "</ul>";
        }
        
        if (!cidr_matcher.empty()) {
            html << R"(<label>Configured IP Ranges</label><div class="cidr-list">)";
            for (const auto& range : cidr_matcher.ranges) {
                html << utils::htmlEscape(range.toString()) << "<br>";
            }
            html << "</div>";
        }
        
        html << R"(
        </div>
        
        <div class="section" id="search-section">
            <h2 class="section-title">Search</h2>
            <form id="search-form">
                <label for="query">Search by hostname or IP address</label>
                <div style="position: relative;">
                    <input type="text" id="query" name="q" placeholder="Enter hostname or IP..." autocomplete="off">
                    <div class="suggestions" id="suggestions"></div>
                </div>
                <button type="submit" id="search-btn">Search</button>
            </form>
        </div>
        
        <div class="section" id="results">
            <h2 class="section-title">Results</h2>
            <div id="results-content"></div>
        </div>
    </div>
    
    <script>
        // File upload and ingestion
        document.getElementById('ingest-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            const btn = document.getElementById('ingest-btn');
            
            btn.disabled = true;
            btn.textContent = 'Processing...';
            
            try {
                const formData = new FormData(form);
                const response = await fetch('/ingest', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error('Ingestion failed: ' + response.statusText);
                }
                
                // Reload page to show updated stats
                window.location.reload();
            } catch (err) {
                alert('Error: ' + err.message);
            } finally {
                btn.disabled = false;
                btn.textContent = 'Ingest & Analyze';
            }
        });
        
        // Search functionality
        const searchForm = document.getElementById('search-form');
        const queryInput = document.getElementById('query');
        const suggestionsDiv = document.getElementById('suggestions');
        const resultsDiv = document.getElementById('results');
        const resultsContent = document.getElementById('results-content');
        
        let debounceTimer = null;
        
        queryInput.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(async () => {
                const q = queryInput.value.trim();
                if (q.length < 2) {
                    suggestionsDiv.classList.remove('active');
                    return;
                }
                
                try {
                    const response = await fetch('/api/suggest?q=' + encodeURIComponent(q));
                    const data = await response.json();
                    
                    if (data.suggestions && data.suggestions.length > 0) {
                        suggestionsDiv.innerHTML = data.suggestions
                            .map(s => '<div class="suggestion">' + escapeHtml(s) + '</div>')
                            .join('');
                        suggestionsDiv.classList.add('active');
                        
                        // Click handler for suggestions
                        suggestionsDiv.querySelectorAll('.suggestion').forEach(el => {
                            el.addEventListener('click', () => {
                                queryInput.value = el.textContent;
                                suggestionsDiv.classList.remove('active');
                                searchForm.dispatchEvent(new Event('submit'));
                            });
                        });
                    } else {
                        suggestionsDiv.classList.remove('active');
                    }
                } catch (err) {
                    console.error('Suggestion error:', err);
                }
            }, 200);
        });
        
        queryInput.addEventListener('blur', () => {
            setTimeout(() => suggestionsDiv.classList.remove('active'), 200);
        });
        
        searchForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const q = queryInput.value.trim();
            if (!q) return;
            
            suggestionsDiv.classList.remove('active');
            resultsDiv.style.display = 'block';
            resultsContent.innerHTML = '<div class="loading">Searching...</div>';
            
            try {
                const response = await fetch('/search?q=' + encodeURIComponent(q));
                const html = await response.text();
                resultsContent.innerHTML = html;
            } catch (err) {
                resultsContent.innerHTML = '<div class="error-msg">Search error: ' + escapeHtml(err.message) + '</div>';
            }
        });
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>)";
        
        return html.str();
    }
    
    // Render search results
    std::string renderSearchResults(const std::string& query, 
                                    const ConnectionGraph& graph,
                                    const CIDRMatcher& cidr_matcher) {
        std::ostringstream html;
        
        auto node_ids = graph.search(query);
        
        if (node_ids.empty()) {
            html << R"(<div class="error-msg">No systems found matching ")" 
                 << utils::htmlEscape(query) << R"("</div>)";
            return html.str();
        }
        
        for (const auto& node_id : node_ids) {
            const auto* node = graph.getNode(node_id);
            if (!node) continue;
            
            html << R"(<div class="node-card">)";
            html << R"(<div class="node-name">)" << utils::htmlEscape(node->getDisplayName()) << "</div>";
            
            // Node metadata
            html << R"(<div class="node-meta">)";
            
            // Hostnames
            for (const auto& hostname : node->hostnames) {
                html << R"(<span class="badge badge-info">)" << utils::htmlEscape(hostname) << "</span>";
            }
            
            // IPs with range indicator
            for (const auto& ip : node->ip_addresses) {
                bool in_range = cidr_matcher.empty() || cidr_matcher.matches(ip);
                html << R"(<span class="badge )" << (in_range ? "badge-success" : "badge-warning") << R"(">)"
                     << utils::htmlEscape(ip.toDisplayString())
                     << (in_range ? " (in range)" : " (out of range)") << "</span>";
            }
            
            html << "</div>";
            
            // Connections table
            auto edges = graph.getEdges(node_id);
            
            if (!edges.empty()) {
                html << R"(<table class="connections-table">
                    <thead>
                        <tr>
                            <th>Peer</th>
                            <th>Local Port</th>
                            <th>Remote Port</th>
                            <th>Direction</th>
                            <th>Service</th>
                            <th>Range</th>
                        </tr>
                    </thead>
                    <tbody>)";
                
                for (const auto* edge : edges) {
                    // Determine peer
                    std::string peer_id = (edge->source_id == node_id) ? edge->dest_id : edge->source_id;
                    const auto* peer = graph.getNode(peer_id);
                    std::string peer_name = peer ? peer->getDisplayName() : "unknown";
                    
                    // Determine if peer is in range
                    bool peer_in_range = false;
                    if (peer) {
                        for (const auto& ip : peer->ip_addresses) {
                            if (cidr_matcher.empty() || cidr_matcher.matches(ip)) {
                                peer_in_range = true;
                                break;
                            }
                        }
                    }
                    
                    html << "<tr>";
                    html << "<td>" << utils::htmlEscape(peer_name) << "</td>";
                    html << R"(<td class="port">)" << edge->local_port << "</td>";
                    html << R"(<td class="port">)" << edge->remote_port << "</td>";
                    html << "<td>" << utils::htmlEscape(edge->direction) << "</td>";
                    html << R"(<td><span class="service">)" << utils::htmlEscape(edge->service_name) 
                         << " (" << edge->service_port << ")</span></td>";
                    html << R"(<td class=")" << (peer_in_range ? "in-range" : "out-range") << R"(">)"
                         << (peer_in_range ? "In Range" : "External") << "</td>";
                    html << "</tr>";
                }
                
                html << "</tbody></table>";
            } else {
                html << "<p>No connections found for this system.</p>";
            }
            
            // Simple SVG topology
            html << renderTopology(node_id, graph, cidr_matcher);
            
            html << "</div>";
        }
        
        return html.str();
    }
    
    // Render simple SVG topology
    std::string renderTopology(const std::string& center_id, 
                               const ConnectionGraph& graph,
                               const CIDRMatcher& cidr_matcher) {
        std::ostringstream svg;
        
        const auto* center = graph.getNode(center_id);
        if (!center) return "";
        
        auto edges = graph.getEdges(center_id);
        if (edges.empty()) return "";
        
        // Collect unique peers
        std::set<std::string> peer_ids;
        for (const auto* edge : edges) {
            std::string peer_id = (edge->source_id == center_id) ? edge->dest_id : edge->source_id;
            peer_ids.insert(peer_id);
        }
        
        // Limit to reasonable number
        std::vector<std::string> peers(peer_ids.begin(), peer_ids.end());
        if (peers.size() > 12) peers.resize(12);
        
        int cx = 400, cy = 180;  // Center position
        int radius = 140;
        
        svg << R"(<div class="topology"><svg viewBox="0 0 800 360">)";
        
        // Build a map of peer_id -> service name for labeling spokes
        std::map<std::string, std::string> peer_services;
        for (const auto* edge : edges) {
            std::string peer_id = (edge->source_id == center_id) ? edge->dest_id : edge->source_id;
            // Get the service name for this edge
            std::string svc = edge->service_name.empty() ? "unknown" : edge->service_name;
            // If we already have a service for this peer, append if different
            auto it = peer_services.find(peer_id);
            if (it == peer_services.end()) {
                peer_services[peer_id] = svc;
            } else if (it->second.find(svc) == std::string::npos && it->second != svc) {
                // Add additional service if different (limit to avoid overflow)
                if (it->second.length() < 20) {
                    it->second += "/" + svc;
                }
            }
        }
        
        // Draw edges with protocol labels
        svg << R"(<g stroke="#30363d" stroke-width="2">)";
        for (size_t i = 0; i < peers.size(); ++i) {
            double angle = (2 * 3.14159 * i) / peers.size() - 3.14159 / 2;
            int px = static_cast<int>(cx + radius * std::cos(angle));
            int py = static_cast<int>(cy + radius * std::sin(angle));
            svg << R"(<line x1=")" << cx << R"(" y1=")" << cy << R"(" x2=")" << px << R"(" y2=")" << py << R"("/>)";
            
            // Add protocol label at midpoint of the line
            int mx = (cx + px) / 2;
            int my = (cy + py) / 2;
            
            // Get the service for this peer
            std::string svc_label = "?";
            auto svc_it = peer_services.find(peers[i]);
            if (svc_it != peer_services.end()) {
                svc_label = svc_it->second;
                // Truncate if too long
                if (svc_label.length() > 12) {
                    svc_label = svc_label.substr(0, 11) + "...";
                }
            }
            
            // Draw a background rect for readability
            svg << R"(<rect x=")" << (mx - 28) << R"(" y=")" << (my - 8) 
                << R"(" width="56" height="16" rx="3" fill="#161b22" stroke="#30363d" stroke-width="1"/>)";
            svg << R"(<text x=")" << mx << R"(" y=")" << (my + 4) 
                << R"(" text-anchor="middle" fill="#8b949e" font-size="10" font-family="monospace">)"
                << utils::htmlEscape(svc_label) << "</text>";
        }
        svg << "</g>";
        
        // Draw center node (larger circle)
        svg << R"(<g>)";
        svg << R"(<circle cx=")" << cx << R"(" cy=")" << cy << R"(" r="50" fill="#58a6ff"/>)";
        svg << R"(<text x=")" << cx << R"(" y=")" << (cy + 5) 
            << R"(" text-anchor="middle" fill="#fff" font-size="10" font-weight="600">)"
            << utils::htmlEscape(center->getDisplayName().substr(0, 16)) << "</text>";
        svg << "</g>";
        
        // Draw peer nodes (larger circles)
        for (size_t i = 0; i < peers.size(); ++i) {
            const auto* peer = graph.getNode(peers[i]);
            if (!peer) continue;
            
            bool in_range = false;
            for (const auto& ip : peer->ip_addresses) {
                if (cidr_matcher.empty() || cidr_matcher.matches(ip)) {
                    in_range = true;
                    break;
                }
            }
            
            double angle = (2 * 3.14159 * i) / peers.size() - 3.14159 / 2;
            int px = static_cast<int>(cx + radius * std::cos(angle));
            int py = static_cast<int>(cy + radius * std::sin(angle));
            
            std::string color = in_range ? "#3fb950" : "#d29922";
            
            svg << R"(<g>)";
            svg << R"(<circle cx=")" << px << R"(" cy=")" << py << R"(" r="40" fill=")" << color << R"("/>)";
            svg << R"(<text x=")" << px << R"(" y=")" << (py + 4) 
                << R"(" text-anchor="middle" fill="#fff" font-size="9">)"
                << utils::htmlEscape(peer->getDisplayName().substr(0, 14)) << "</text>";
            svg << "</g>";
        }
        
        svg << "</svg></div>";
        
        return svg.str();
    }

private:
    const ServiceMapper& service_mapper_;
};

// ============================================================================
// Multipart Parser
// ============================================================================

/**
 * Parses multipart/form-data requests for file uploads
 */
class MultipartParser {
public:
    struct Part {
        std::string name;
        std::string filename;
        std::string content_type;
        std::string data;
    };
    
    static std::vector<Part> parse(const std::string& body, const std::string& boundary) {
        std::vector<Part> parts;
        
        std::string delimiter = "--" + boundary;
        std::string end_delimiter = delimiter + "--";
        
        size_t pos = 0;
        while (true) {
            // Find start of part
            size_t start = body.find(delimiter, pos);
            if (start == std::string::npos) break;
            start += delimiter.size();
            
            // Skip CRLF after delimiter
            if (start < body.size() && body[start] == '\r') start++;
            if (start < body.size() && body[start] == '\n') start++;
            
            // Check for end delimiter
            if (body.substr(start, 2) == "--") break;
            
            // Find end of part
            size_t end = body.find(delimiter, start);
            if (end == std::string::npos) break;
            
            // Remove trailing CRLF before delimiter
            if (end >= 2 && body[end - 2] == '\r' && body[end - 1] == '\n') {
                end -= 2;
            }
            
            // Parse part
            std::string part_data = body.substr(start, end - start);
            auto part = parsePart(part_data);
            if (!part.name.empty()) {
                parts.push_back(part);
            }
            
            pos = end;
        }
        
        return parts;
    }
    
private:
    static Part parsePart(const std::string& data) {
        Part part;
        
        // Find header/body separator (blank line)
        size_t header_end = data.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            header_end = data.find("\n\n");
            if (header_end == std::string::npos) return part;
        }
        
        std::string headers = data.substr(0, header_end);
        size_t body_start = header_end + (data[header_end] == '\r' ? 4 : 2);
        part.data = data.substr(body_start);
        
        // Parse headers
        std::istringstream iss(headers);
        std::string line;
        while (std::getline(iss, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            
            // Content-Disposition
            if (utils::startsWith(utils::toLower(line), "content-disposition:")) {
                // Extract name
                size_t name_pos = line.find("name=\"");
                if (name_pos != std::string::npos) {
                    name_pos += 6;
                    size_t name_end = line.find('"', name_pos);
                    if (name_end != std::string::npos) {
                        part.name = line.substr(name_pos, name_end - name_pos);
                    }
                }
                
                // Extract filename
                size_t filename_pos = line.find("filename=\"");
                if (filename_pos != std::string::npos) {
                    filename_pos += 10;
                    size_t filename_end = line.find('"', filename_pos);
                    if (filename_end != std::string::npos) {
                        part.filename = line.substr(filename_pos, filename_end - filename_pos);
                        // Sanitize filename (remove path components)
                        size_t last_slash = part.filename.find_last_of("/\\");
                        if (last_slash != std::string::npos) {
                            part.filename = part.filename.substr(last_slash + 1);
                        }
                    }
                }
            }
            
            // Content-Type
            if (utils::startsWith(utils::toLower(line), "content-type:")) {
                part.content_type = utils::trim(line.substr(13));
            }
        }
        
        return part;
    }
};

// ============================================================================
// HTTP Server
// ============================================================================

/**
 * Simple HTTP/1.1 server bound to localhost only
 */
class HttpServer {
public:
    struct Request {
        std::string method;
        std::string path;
        std::string query_string;
        std::map<std::string, std::string> headers;
        std::string body;
        std::map<std::string, std::string> query_params;
    };
    
    struct Response {
        int status_code = 200;
        std::string status_text = "OK";
        std::map<std::string, std::string> headers;
        std::string body;
        
        void setContentType(const std::string& type) {
            headers["Content-Type"] = type;
        }
        
        void setHtml(const std::string& html) {
            setContentType("text/html; charset=utf-8");
            body = html;
        }
        
        void setJson(const std::string& json) {
            setContentType("application/json");
            body = json;
        }
        
        void setError(int code, const std::string& message) {
            status_code = code;
            status_text = message;
            setContentType("text/plain");
            body = message;
        }
    };
    
    using Handler = std::function<void(const Request&, Response&)>;
    
    HttpServer(const std::string& bind_address, int port)
        : bind_address_(bind_address), port_(port), server_fd_(-1) {}
    
    ~HttpServer() {
        if (server_fd_ >= 0) {
            close(server_fd_);
        }
    }
    
    // Add route handler
    void route(const std::string& method, const std::string& path, Handler handler) {
        routes_[method + " " + path] = handler;
    }
    
    // Start server
    bool start() {
        // Create socket
        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ < 0) {
            std::cerr << "Error creating socket: " << strerror(errno) << std::endl;
            return false;
        }
        
        // Set socket options
        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        // Bind
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        
        if (inet_pton(AF_INET, bind_address_.c_str(), &addr.sin_addr) != 1) {
            std::cerr << "Invalid bind address: " << bind_address_ << std::endl;
            return false;
        }
        
        if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Error binding to " << bind_address_ << ":" << port_ 
                      << ": " << strerror(errno) << std::endl;
            return false;
        }
        
        // Listen
        if (listen(server_fd_, BACKLOG) < 0) {
            std::cerr << "Error listening: " << strerror(errno) << std::endl;
            return false;
        }
        
        std::cout << "Server started at http://" << bind_address_ << ":" << port_ << std::endl;
        std::cout << "Press Ctrl+C to stop" << std::endl;
        
        // Accept loop
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept(server_fd_, (struct sockaddr*)&client_addr, &client_len);
            if (client_fd < 0) {
                if (running_) {
                    std::cerr << "Error accepting connection: " << strerror(errno) << std::endl;
                }
                continue;
            }
            
            handleConnection(client_fd);
        }
        
        return true;
    }
    
    void stop() {
        running_ = false;
        if (server_fd_ >= 0) {
            shutdown(server_fd_, SHUT_RDWR);
        }
    }

private:
    std::string bind_address_;
    int port_;
    int server_fd_;
    bool running_ = true;
    std::map<std::string, Handler> routes_;
    
    void handleConnection(int client_fd) {
        // Read request with size limit
        std::string request_data;
        request_data.reserve(BUFFER_SIZE);
        
        char buffer[BUFFER_SIZE];
        size_t total_read = 0;
        size_t content_length = 0;
        bool headers_done = false;
        size_t header_end = 0;
        
        while (total_read < MAX_REQUEST_SIZE) {
            ssize_t n = recv(client_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            
            request_data.append(buffer, n);
            total_read += n;
            
            // Check if we have complete headers
            if (!headers_done) {
                header_end = request_data.find("\r\n\r\n");
                if (header_end != std::string::npos) {
                    headers_done = true;
                    
                    // Extract Content-Length
                    std::string headers = request_data.substr(0, header_end);
                    size_t cl_pos = headers.find("Content-Length:");
                    if (cl_pos == std::string::npos) {
                        cl_pos = headers.find("content-length:");
                    }
                    if (cl_pos != std::string::npos) {
                        size_t cl_end = headers.find("\r\n", cl_pos);
                        std::string cl_str = headers.substr(cl_pos + 15, cl_end - cl_pos - 15);
                        try {
                            content_length = std::stoull(utils::trim(cl_str));
                        } catch (...) {}
                    }
                }
            }
            
            // Check if we have complete body
            if (headers_done) {
                size_t body_start = header_end + 4;
                if (request_data.size() >= body_start + content_length) {
                    break;
                }
            }
        }
        
        // Parse and handle request
        Request request;
        Response response;
        
        if (parseRequest(request_data, request)) {
            // Find handler
            std::string route_key = request.method + " " + request.path;
            auto it = routes_.find(route_key);
            if (it != routes_.end()) {
                try {
                    it->second(request, response);
                } catch (const std::exception& e) {
                    response.setError(500, "Internal Server Error: " + std::string(e.what()));
                }
            } else {
                response.setError(404, "Not Found");
            }
        } else {
            response.setError(400, "Bad Request");
        }
        
        // Send response
        sendResponse(client_fd, response);
        close(client_fd);
    }
    
    bool parseRequest(const std::string& data, Request& request) {
        // Find header end
        size_t header_end = data.find("\r\n\r\n");
        if (header_end == std::string::npos) return false;
        
        std::string headers = data.substr(0, header_end);
        request.body = data.substr(header_end + 4);
        
        // Parse request line
        size_t first_line_end = headers.find("\r\n");
        if (first_line_end == std::string::npos) return false;
        
        std::string request_line = headers.substr(0, first_line_end);
        std::istringstream iss(request_line);
        std::string version;
        iss >> request.method >> request.path >> version;
        
        if (request.method.empty() || request.path.empty()) return false;
        
        // Extract query string
        size_t query_pos = request.path.find('?');
        if (query_pos != std::string::npos) {
            request.query_string = request.path.substr(query_pos + 1);
            request.path = request.path.substr(0, query_pos);
            request.query_params = utils::parseQueryString(request.query_string);
        }
        
        // Parse headers
        size_t pos = first_line_end + 2;
        while (pos < header_end) {
            size_t line_end = headers.find("\r\n", pos);
            if (line_end == std::string::npos) break;
            
            std::string line = headers.substr(pos, line_end - pos);
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string key = utils::trim(line.substr(0, colon));
                std::string value = utils::trim(line.substr(colon + 1));
                request.headers[utils::toLower(key)] = value;
            }
            
            pos = line_end + 2;
        }
        
        return true;
    }
    
    void sendResponse(int client_fd, Response& response) {
        std::ostringstream oss;
        
        // Status line
        oss << "HTTP/1.1 " << response.status_code << " " << response.status_text << "\r\n";
        
        // Headers
        response.headers["Content-Length"] = std::to_string(response.body.size());
        response.headers["Connection"] = "close";
        
        for (const auto& [key, value] : response.headers) {
            oss << key << ": " << value << "\r\n";
        }
        
        oss << "\r\n";
        oss << response.body;
        
        std::string response_str = oss.str();
        send(client_fd, response_str.c_str(), response_str.size(), 0);
    }
};

// ============================================================================
// Application State
// ============================================================================

/**
 * Global application state
 */
class MapperApp {
public:
    MapperApp() : renderer_(service_mapper_) {}
    
    ConnectionGraph graph;
    CIDRMatcher cidr_matcher;
    ServiceMapper service_mapper_;
    HtmlRenderer renderer_;
    GatherdParser parser_;
    
    std::vector<std::string> ingested_files;
    int total_accepted = 0;
    int total_rejected = 0;
    std::vector<std::string> parse_errors;
};

// ============================================================================
// Main Application
// ============================================================================

MapperApp* g_app = nullptr;

void signalHandler(int) {
    std::cout << "\nShutting down..." << std::endl;
    exit(0);
}

void printUsage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n"
              << "\nOptions:\n"
              << "  --port PORT      Port to listen on (default: 8080)\n"
              << "  --bind ADDRESS   Address to bind to (default: 127.0.0.1)\n"
              << "  --help           Show this help message\n"
              << "\nSecurity Note:\n"
              << "  This application binds to localhost (127.0.0.1) by default and does not\n"
              << "  implement authentication. It is intended for local analysis only.\n"
              << "  Do not expose to external networks.\n"
              << "\nDescription:\n"
              << "  mapper is a web application for analyzing gatherd connection data.\n"
              << "  It ingests gatherd output files (JSON or text format), normalizes the\n"
              << "  connection data, and provides a searchable interface to explore system\n"
              << "  interconnections based on port usage and service mappings.\n";
}

int main(int argc, char* argv[]) {
    std::string bind_address = DEFAULT_BIND_ADDRESS;
    int port = DEFAULT_PORT;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "--port" && i + 1 < argc) {
            try {
                port = std::stoi(argv[++i]);
                if (port < 1 || port > 65535) {
                    std::cerr << "Error: Port must be between 1 and 65535" << std::endl;
                    return 1;
                }
            } catch (...) {
                std::cerr << "Error: Invalid port number" << std::endl;
                return 1;
            }
        } else if (arg == "--bind" && i + 1 < argc) {
            bind_address = argv[++i];
            // Warn if not localhost
            if (bind_address != "127.0.0.1" && bind_address != "localhost" && bind_address != "::1") {
                std::cerr << "WARNING: Binding to non-localhost address (" << bind_address << ").\n"
                          << "         This application has no authentication and should only be\n"
                          << "         used on trusted local networks.\n";
            }
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }
    
    // Set up signal handler
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Initialize application
    MapperApp app;
    g_app = &app;
    
    // Create HTTP server
    HttpServer server(bind_address, port);
    
    // Route: Main page
    server.route("GET", "/", [&app](const HttpServer::Request&, HttpServer::Response& res) {
        res.setHtml(app.renderer_.renderMainPage(
            app.graph, app.cidr_matcher, app.ingested_files,
            app.total_accepted, app.total_rejected
        ));
    });
    
    // Route: File ingestion
    server.route("POST", "/ingest", [&app](const HttpServer::Request& req, HttpServer::Response& res) {
        // Extract boundary from Content-Type header
        auto ct_it = req.headers.find("content-type");
        if (ct_it == req.headers.end()) {
            res.setError(400, "Missing Content-Type header");
            return;
        }
        
        std::string content_type = ct_it->second;
        size_t boundary_pos = content_type.find("boundary=");
        if (boundary_pos == std::string::npos) {
            res.setError(400, "Missing boundary in Content-Type");
            return;
        }
        
        std::string boundary = content_type.substr(boundary_pos + 9);
        // Remove quotes if present
        if (!boundary.empty() && boundary.front() == '"') {
            boundary = boundary.substr(1);
            size_t end_quote = boundary.find('"');
            if (end_quote != std::string::npos) {
                boundary = boundary.substr(0, end_quote);
            }
        }
        
        // Parse multipart data
        auto parts = MultipartParser::parse(req.body, boundary);
        
        // Clear previous data
        app.graph.clear();
        app.ingested_files.clear();
        app.total_accepted = 0;
        app.total_rejected = 0;
        app.parse_errors.clear();
        
        // Process CIDR ranges first
        for (const auto& part : parts) {
            if (part.name == "cidr") {
                auto [parsed, errors] = app.cidr_matcher.parseRanges(part.data);
                for (const auto& err : errors) {
                    app.parse_errors.push_back(err);
                }
            }
        }
        
        // Process uploaded files
        for (const auto& part : parts) {
            if (part.name == "files" && !part.filename.empty() && !part.data.empty()) {
                auto result = app.parser_.parse(part.data, part.filename);
                
                app.total_accepted += result.accepted;
                app.total_rejected += result.rejected;
                
                for (const auto& err : result.errors) {
                    app.parse_errors.push_back(part.filename + ": " + err);
                }
                
                if (!result.records.empty()) {
                    app.graph.ingest(result.records, app.cidr_matcher, app.service_mapper_);
                    app.ingested_files.push_back(part.filename);
                }
            }
        }
        
        // Redirect back to main page
        res.status_code = 303;
        res.status_text = "See Other";
        res.headers["Location"] = "/";
        res.body = "";
    });
    
    // Route: Search
    server.route("GET", "/search", [&app](const HttpServer::Request& req, HttpServer::Response& res) {
        auto it = req.query_params.find("q");
        if (it == req.query_params.end() || it->second.empty()) {
            res.setHtml("<div class=\"error-msg\">No search query provided</div>");
            return;
        }
        
        std::string html = app.renderer_.renderSearchResults(it->second, app.graph, app.cidr_matcher);
        res.setHtml(html);
    });
    
    // Route: Suggestions API
    server.route("GET", "/api/suggest", [&app](const HttpServer::Request& req, HttpServer::Response& res) {
        auto it = req.query_params.find("q");
        std::string query = (it != req.query_params.end()) ? it->second : "";
        
        auto suggestions = app.graph.getSuggestions(query, 10);
        
        std::ostringstream json;
        json << "{\"suggestions\":[";
        for (size_t i = 0; i < suggestions.size(); ++i) {
            if (i > 0) json << ",";
            json << "\"";
            // Escape JSON string
            for (char c : suggestions[i]) {
                switch (c) {
                    case '"': json << "\\\""; break;
                    case '\\': json << "\\\\"; break;
                    case '\n': json << "\\n"; break;
                    case '\r': json << "\\r"; break;
                    case '\t': json << "\\t"; break;
                    default: json << c;
                }
            }
            json << "\"";
        }
        json << "]}";
        
        res.setJson(json.str());
    });
    
    // Route: Status API
    server.route("GET", "/api/status", [&app](const HttpServer::Request&, HttpServer::Response& res) {
        std::ostringstream json;
        json << "{";
        json << "\"files_ingested\":" << app.ingested_files.size() << ",";
        json << "\"records_accepted\":" << app.total_accepted << ",";
        json << "\"records_rejected\":" << app.total_rejected << ",";
        json << "\"unique_connections\":" << app.graph.uniqueRecordCount() << ",";
        json << "\"nodes\":" << app.graph.nodeCount() << ",";
        json << "\"edges\":" << app.graph.edgeCount() << ",";
        json << "\"cidr_ranges\":" << app.cidr_matcher.ranges.size();
        json << "}";
        
        res.setJson(json.str());
    });
    
    // Start server
    if (!server.start()) {
        return 1;
    }
    
    return 0;
}

