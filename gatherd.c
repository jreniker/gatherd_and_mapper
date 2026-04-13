/*
 * gatherd.c - Network Connection Gatherer for Red Hat Enterprise Linux 7
 *
 * DESCRIPTION:
 *   A low-impact utility that gathers active network connection data from
 *   /proc/net/* and outputs a unique, colon-separated list of connections.
 *   Designed to run from cron or command line with minimal resource usage.
 *
 * COMPILATION:
 *   gcc -O2 -std=c99 -Wall -Wextra -pedantic -o gatherd gatherd.c
 *
 * USAGE:
 *   gatherd [-o OUTPUT] [-json] [-h|--help]
 *
 * OUTPUT FORMAT (text mode):
 *   hostname:local_ip:local_port:remote_ip:remote_port:direction
 *
 * OUTPUT FORMAT (JSON mode):
 *   Array of objects with keys: hostname, local_ip, local_port, remote_ip,
 *   remote_port, direction
 *
 * DIRECTION HEURISTIC:
 *   The kernel does not directly expose connection direction. We use the
 *   following heuristic to classify connections:
 *
 *   1. Read /proc/sys/net/ipv4/ip_local_port_range to determine the ephemeral
 *      port range (typically 32768-60999 on RHEL 7).
 *
 *   2. For TCP connections:
 *      - If the connection is in LISTEN state, skip it (not an active connection)
 *      - If local_port < ephemeral_low AND remote_port >= ephemeral_low:
 *        Classify as INBOUND (client connected to our service port)
 *      - If local_port >= ephemeral_low AND remote_port < ephemeral_low:
 *        Classify as OUTBOUND (we connected to a remote service)
 *      - Otherwise: Use local_port < remote_port as tiebreaker
 *        (lower port is typically the service side, hence Inbound)
 *
 *   3. For UDP sockets:
 *      - UDP is connectionless; we include only sockets with a specified
 *        remote endpoint (non-zero remote address and port)
 *      - Apply similar port-based heuristic as TCP
 *
 *   LIMITATIONS:
 *   - This heuristic may misclassify connections where both ports are in
 *     the same range (both ephemeral or both well-known)
 *   - NAT and port forwarding can affect accuracy
 *   - Some applications use non-standard port ranges
 *
 * TCP STATES INCLUDED:
 *   We include ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1, FIN_WAIT2,
 *   TIME_WAIT, CLOSE_WAIT, LAST_ACK, and CLOSING states.
 *   We exclude LISTEN (not an active connection) and CLOSE (fully closed).
 *
 * UDP FILTERING:
 *   UDP sockets with unspecified remote endpoints (0.0.0.0:0 or [::]:0)
 *   are excluded as they represent listening/unconnected sockets, not
 *   active connections.
 *
 * AUTHOR: Generated for RHEL 7 deployment
 * LICENSE: Public Domain / MIT
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <ctype.h>

/* Maximum connections we can store (adjust if needed) */
#define MAX_CONNECTIONS 65536

/* Maximum hostname length */
#define MAX_HOSTNAME 256

/* Maximum line length when reading /proc files */
#define MAX_LINE 512

/* Maximum IP address string length (IPv6 with brackets) */
#define MAX_IP_STR 48

/* TCP states from kernel (include/net/tcp_states.h) */
#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_SYN_RECV     3
#define TCP_FIN_WAIT1    4
#define TCP_FIN_WAIT2    5
#define TCP_TIME_WAIT    6
#define TCP_CLOSE        7
#define TCP_CLOSE_WAIT   8
#define TCP_LAST_ACK     9
#define TCP_LISTEN      10
#define TCP_CLOSING     11

/* Direction enumeration */
typedef enum {
    DIR_INBOUND,
    DIR_OUTBOUND
} direction_t;

/* Connection record structure */
typedef struct {
    char hostname[MAX_HOSTNAME];
    char local_ip[MAX_IP_STR];
    uint16_t local_port;
    char remote_ip[MAX_IP_STR];
    uint16_t remote_port;
    direction_t direction;
    int is_ipv6;
} connection_t;

/* Global state */
static connection_t g_connections[MAX_CONNECTIONS];
static size_t g_conn_count = 0;
static char g_hostname[MAX_HOSTNAME];
static uint16_t g_ephemeral_low = 32768;   /* Default ephemeral port range */
static uint16_t g_ephemeral_high = 60999;

/* Function prototypes */
static void print_usage(const char *progname);
static int read_ephemeral_port_range(void);
static int parse_ipv4_addr(const char *hex, char *out, size_t out_size);
static int parse_ipv6_addr(const char *hex, char *out, size_t out_size);
static uint16_t parse_port(const char *hex);
static direction_t classify_direction(uint16_t local_port, uint16_t remote_port);
static int is_zero_address(const char *ip, int is_ipv6);
static int process_proc_file(const char *path, int is_ipv6, int is_tcp);
static int add_connection(const connection_t *conn);
static int connection_compare(const void *a, const void *b);
static void deduplicate_connections(void);
static void output_text(FILE *out);
static void output_json(FILE *out);
static void escape_json_string(FILE *out, const char *str);

/*
 * Print usage information to stdout
 */
static void print_usage(const char *progname)
{
    printf("Usage: %s [-o OUTPUT] [-json] [-h|--help]\n", progname);
    printf("\n");
    printf("Gather active network connections and output a deduplicated list.\n");
    printf("\n");
    printf("Options:\n");
    printf("  -o OUTPUT   Write output to specified file (default: stdout)\n");
    printf("  -json       Output in JSON format instead of colon-separated text\n");
    printf("  -h, --help  Show this help message and exit\n");
    printf("\n");
    printf("Text output format:\n");
    printf("  hostname:local_ip:local_port:remote_ip:remote_port:direction\n");
    printf("\n");
    printf("IPv6 addresses are enclosed in square brackets.\n");
    printf("Direction is either 'Inbound' or 'Outbound'.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                     # Output to stdout\n", progname);
    printf("  %s -o /tmp/conns.txt   # Output to file\n", progname);
    printf("  %s -json               # JSON to stdout\n", progname);
    printf("  %s -o /tmp/conns.json -json\n", progname);
}

/*
 * Read the ephemeral port range from /proc/sys/net/ipv4/ip_local_port_range
 * Returns 0 on success, -1 on failure (uses defaults on failure)
 */
static int read_ephemeral_port_range(void)
{
    FILE *fp;
    unsigned int low, high;

    fp = fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");
    if (fp == NULL) {
        /* Use defaults, not a fatal error */
        return -1;
    }

    if (fscanf(fp, "%u %u", &low, &high) == 2) {
        if (low <= 65535 && high <= 65535 && low < high) {
            g_ephemeral_low = (uint16_t)low;
            g_ephemeral_high = (uint16_t)high;
        }
    }

    fclose(fp);
    return 0;
}

/*
 * Parse an IPv4 address from kernel hex format (little-endian 32-bit)
 * Input: 8 hex characters (e.g., "0100007F" for 127.0.0.1)
 * Output: Dotted decimal string
 * Returns 0 on success, -1 on failure
 */
static int parse_ipv4_addr(const char *hex, char *out, size_t out_size)
{
    unsigned int addr;
    unsigned char bytes[4];

    if (strlen(hex) < 8) {
        return -1;
    }

    /* Parse as big-endian hex, but kernel stores it in host byte order */
    if (sscanf(hex, "%8X", &addr) != 1) {
        return -1;
    }

    /*
     * The kernel stores IPv4 addresses in /proc/net/* in host byte order
     * as a hex string. On little-endian systems (x86), we need to interpret
     * it correctly. The format is already in network byte order when read.
     */
    bytes[0] = (addr >> 0) & 0xFF;
    bytes[1] = (addr >> 8) & 0xFF;
    bytes[2] = (addr >> 16) & 0xFF;
    bytes[3] = (addr >> 24) & 0xFF;

    snprintf(out, out_size, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
    return 0;
}

/*
 * Parse an IPv6 address from kernel hex format
 * Input: 32 hex characters representing 4 32-bit words in host byte order
 * Output: Bracketed IPv6 address string (e.g., "[2001:db8::1]")
 * Returns 0 on success, -1 on failure
 */
static int parse_ipv6_addr(const char *hex, char *out, size_t out_size)
{
    unsigned char addr[16];
    unsigned int word;
    char ipstr[INET6_ADDRSTRLEN];
    int i;

    if (strlen(hex) < 32) {
        return -1;
    }

    /*
     * The kernel stores IPv6 addresses as 4 32-bit words in host byte order.
     * Each word is 8 hex characters. We need to parse each word and extract
     * the bytes in the correct order for inet_ntop.
     */
    for (i = 0; i < 4; i++) {
        if (sscanf(hex + (i * 8), "%8X", &word) != 1) {
            return -1;
        }
        /* Each 32-bit word is stored in host byte order */
        addr[i * 4 + 0] = (word >> 0) & 0xFF;
        addr[i * 4 + 1] = (word >> 8) & 0xFF;
        addr[i * 4 + 2] = (word >> 16) & 0xFF;
        addr[i * 4 + 3] = (word >> 24) & 0xFF;
    }

    /* Convert binary address to string */
    if (inet_ntop(AF_INET6, addr, ipstr, sizeof(ipstr)) == NULL) {
        return -1;
    }

    /* Wrap in brackets for output */
    snprintf(out, out_size, "[%s]", ipstr);
    return 0;
}

/*
 * Parse a port number from 4-character hex string
 * Returns the port number (already in host byte order from kernel)
 */
static uint16_t parse_port(const char *hex)
{
    unsigned int port;

    if (sscanf(hex, "%4X", &port) != 1) {
        return 0;
    }

    return (uint16_t)port;
}

/*
 * Classify connection direction based on port numbers
 *
 * Heuristic:
 * - If local port is below ephemeral range and remote port is in ephemeral range:
 *   This suggests a client connected to our service -> Inbound
 * - If local port is in ephemeral range and remote port is below ephemeral range:
 *   This suggests we connected to a remote service -> Outbound
 * - Otherwise, use local_port < remote_port as tiebreaker (lower port = service)
 */
static direction_t classify_direction(uint16_t local_port, uint16_t remote_port)
{
    int local_is_ephemeral = (local_port >= g_ephemeral_low && local_port <= g_ephemeral_high);
    int remote_is_ephemeral = (remote_port >= g_ephemeral_low && remote_port <= g_ephemeral_high);

    if (!local_is_ephemeral && remote_is_ephemeral) {
        /* Local is service port, remote is ephemeral -> client connected to us */
        return DIR_INBOUND;
    }

    if (local_is_ephemeral && !remote_is_ephemeral) {
        /* Local is ephemeral, remote is service port -> we connected out */
        return DIR_OUTBOUND;
    }

    /*
     * Ambiguous case: both in same range or both outside
     * Use lower port number as the service side
     */
    if (local_port <= remote_port) {
        return DIR_INBOUND;
    } else {
        return DIR_OUTBOUND;
    }
}

/*
 * Check if an IP address is the zero/unspecified address
 */
static int is_zero_address(const char *ip, int is_ipv6)
{
    if (is_ipv6) {
        /* Check for [::] or [0:0:0:0:0:0:0:0] */
        return (strcmp(ip, "[::]") == 0 ||
                strcmp(ip, "[0:0:0:0:0:0:0:0]") == 0 ||
                strcmp(ip, "[::0]") == 0);
    } else {
        return (strcmp(ip, "0.0.0.0") == 0);
    }
}

/*
 * Process a /proc/net/* file and extract connections
 *
 * File format (TCP/UDP):
 * sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid ...
 *  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0 ...
 *
 * Fields are space-separated, addresses are HEX_IP:HEX_PORT
 *
 * Returns 0 on success, -1 on failure
 */
static int process_proc_file(const char *path, int is_ipv6, int is_tcp)
{
    FILE *fp;
    char line[MAX_LINE];
    int line_num = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        /* File might not exist (e.g., no IPv6), not fatal */
        if (errno == ENOENT) {
            return 0;
        }
        fprintf(stderr, "gatherd: warning: cannot open %s: %s\n", path, strerror(errno));
        return 0; /* Continue with other files */
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char local_addr_hex[64], remote_addr_hex[64];
        char local_ip_hex[40], local_port_hex[8];
        char remote_ip_hex[40], remote_port_hex[8];
        unsigned int state;
        connection_t conn;
        char *colon;

        line_num++;

        /* Skip header line */
        if (line_num == 1) {
            continue;
        }

        /* Parse the line - format varies slightly but key fields are consistent */
        /* sl local_address remote_address st ... */
        if (sscanf(line, "%*d: %63s %63s %X", local_addr_hex, remote_addr_hex, &state) != 3) {
            /* Malformed line, skip */
            continue;
        }

        /* For TCP, filter by state */
        if (is_tcp) {
            /* Skip LISTEN state - not an active connection */
            if (state == TCP_LISTEN) {
                continue;
            }
            /* Skip CLOSE state - fully closed */
            if (state == TCP_CLOSE) {
                continue;
            }
            /* Include: ESTABLISHED, SYN_SENT, SYN_RECV, FIN_WAIT1, FIN_WAIT2,
             * TIME_WAIT, CLOSE_WAIT, LAST_ACK, CLOSING */
        }

        /* Split local address into IP and port */
        colon = strchr(local_addr_hex, ':');
        if (colon == NULL) {
            continue;
        }
        *colon = '\0';
        strncpy(local_ip_hex, local_addr_hex, sizeof(local_ip_hex) - 1);
        local_ip_hex[sizeof(local_ip_hex) - 1] = '\0';
        strncpy(local_port_hex, colon + 1, sizeof(local_port_hex) - 1);
        local_port_hex[sizeof(local_port_hex) - 1] = '\0';

        /* Split remote address into IP and port */
        colon = strchr(remote_addr_hex, ':');
        if (colon == NULL) {
            continue;
        }
        *colon = '\0';
        strncpy(remote_ip_hex, remote_addr_hex, sizeof(remote_ip_hex) - 1);
        remote_ip_hex[sizeof(remote_ip_hex) - 1] = '\0';
        strncpy(remote_port_hex, colon + 1, sizeof(remote_port_hex) - 1);
        remote_port_hex[sizeof(remote_port_hex) - 1] = '\0';

        /* Parse addresses */
        memset(&conn, 0, sizeof(conn));
        conn.is_ipv6 = is_ipv6;
        strncpy(conn.hostname, g_hostname, sizeof(conn.hostname) - 1);

        if (is_ipv6) {
            if (parse_ipv6_addr(local_ip_hex, conn.local_ip, sizeof(conn.local_ip)) != 0) {
                continue;
            }
            if (parse_ipv6_addr(remote_ip_hex, conn.remote_ip, sizeof(conn.remote_ip)) != 0) {
                continue;
            }
        } else {
            if (parse_ipv4_addr(local_ip_hex, conn.local_ip, sizeof(conn.local_ip)) != 0) {
                continue;
            }
            if (parse_ipv4_addr(remote_ip_hex, conn.remote_ip, sizeof(conn.remote_ip)) != 0) {
                continue;
            }
        }

        conn.local_port = parse_port(local_port_hex);
        conn.remote_port = parse_port(remote_port_hex);

        /*
         * For UDP: skip entries with unspecified remote endpoint
         * (these are listening/unconnected sockets, not active connections)
         */
        if (!is_tcp) {
            if (is_zero_address(conn.remote_ip, is_ipv6) && conn.remote_port == 0) {
                continue;
            }
        }

        /* Classify direction */
        conn.direction = classify_direction(conn.local_port, conn.remote_port);

        /* Add to our list */
        if (add_connection(&conn) != 0) {
            fprintf(stderr, "gatherd: warning: connection list full, some entries skipped\n");
            break;
        }
    }

    fclose(fp);
    return 0;
}

/*
 * Add a connection to the global list
 * Returns 0 on success, -1 if list is full
 */
static int add_connection(const connection_t *conn)
{
    if (g_conn_count >= MAX_CONNECTIONS) {
        return -1;
    }

    memcpy(&g_connections[g_conn_count], conn, sizeof(connection_t));
    g_conn_count++;
    return 0;
}

/*
 * Comparison function for sorting connections
 * Sort order: hostname, local_ip, local_port, remote_ip, remote_port, direction
 */
static int connection_compare(const void *a, const void *b)
{
    const connection_t *ca = (const connection_t *)a;
    const connection_t *cb = (const connection_t *)b;
    int cmp;

    cmp = strcmp(ca->hostname, cb->hostname);
    if (cmp != 0) return cmp;

    cmp = strcmp(ca->local_ip, cb->local_ip);
    if (cmp != 0) return cmp;

    if (ca->local_port != cb->local_port) {
        return (ca->local_port < cb->local_port) ? -1 : 1;
    }

    cmp = strcmp(ca->remote_ip, cb->remote_ip);
    if (cmp != 0) return cmp;

    if (ca->remote_port != cb->remote_port) {
        return (ca->remote_port < cb->remote_port) ? -1 : 1;
    }

    if (ca->direction != cb->direction) {
        return (ca->direction < cb->direction) ? -1 : 1;
    }

    return 0;
}

/*
 * Sort and deduplicate the connection list
 */
static void deduplicate_connections(void)
{
    size_t i, j;

    if (g_conn_count <= 1) {
        return;
    }

    /* Sort first */
    qsort(g_connections, g_conn_count, sizeof(connection_t), connection_compare);

    /* Remove consecutive duplicates */
    j = 0;
    for (i = 1; i < g_conn_count; i++) {
        if (connection_compare(&g_connections[j], &g_connections[i]) != 0) {
            j++;
            if (j != i) {
                memcpy(&g_connections[j], &g_connections[i], sizeof(connection_t));
            }
        }
    }
    g_conn_count = j + 1;
}

/*
 * Output connections in text format (colon-separated)
 */
static void output_text(FILE *out)
{
    size_t i;
    const char *dir_str;

    for (i = 0; i < g_conn_count; i++) {
        const connection_t *c = &g_connections[i];

        dir_str = (c->direction == DIR_INBOUND) ? "Inbound" : "Outbound";

        fprintf(out, "%s:%s:%u:%s:%u:%s\n",
                c->hostname,
                c->local_ip,
                (unsigned)c->local_port,
                c->remote_ip,
                (unsigned)c->remote_port,
                dir_str);
    }
}

/*
 * Escape a string for JSON output
 */
static void escape_json_string(FILE *out, const char *str)
{
    const char *p;

    fputc('"', out);
    for (p = str; *p != '\0'; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\b': fputs("\\b", out); break;
            case '\f': fputs("\\f", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if ((unsigned char)*p < 0x20) {
                    fprintf(out, "\\u%04x", (unsigned char)*p);
                } else {
                    fputc(*p, out);
                }
                break;
        }
    }
    fputc('"', out);
}

/*
 * Output connections in JSON format
 */
static void output_json(FILE *out)
{
    size_t i;
    const char *dir_str;

    fputs("[\n", out);

    for (i = 0; i < g_conn_count; i++) {
        const connection_t *c = &g_connections[i];

        dir_str = (c->direction == DIR_INBOUND) ? "Inbound" : "Outbound";

        fputs("  {\n", out);

        fputs("    \"hostname\": ", out);
        escape_json_string(out, c->hostname);
        fputs(",\n", out);

        fputs("    \"local_ip\": ", out);
        escape_json_string(out, c->local_ip);
        fputs(",\n", out);

        fprintf(out, "    \"local_port\": %u,\n", (unsigned)c->local_port);

        fputs("    \"remote_ip\": ", out);
        escape_json_string(out, c->remote_ip);
        fputs(",\n", out);

        fprintf(out, "    \"remote_port\": %u,\n", (unsigned)c->remote_port);

        fputs("    \"direction\": ", out);
        escape_json_string(out, dir_str);
        fputs("\n", out);

        if (i < g_conn_count - 1) {
            fputs("  },\n", out);
        } else {
            fputs("  }\n", out);
        }
    }

    fputs("]\n", out);
}

/*
 * Main entry point
 */
int main(int argc, char *argv[])
{
    const char *output_path = NULL;
    int json_mode = 0;
    FILE *output_file = NULL;
    int i;
    int exit_code = 0;

    /* Parse command line arguments */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-json") == 0) {
            json_mode = 1;
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "gatherd: error: -o requires an argument\n");
                return 1;
            }
            output_path = argv[++i];
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "gatherd: error: unknown option: %s\n", argv[i]);
            fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
            return 1;
        } else {
            fprintf(stderr, "gatherd: error: unexpected argument: %s\n", argv[i]);
            fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
            return 1;
        }
    }

    /* Get hostname */
    if (gethostname(g_hostname, sizeof(g_hostname)) != 0) {
        fprintf(stderr, "gatherd: error: cannot get hostname: %s\n", strerror(errno));
        strncpy(g_hostname, "unknown", sizeof(g_hostname) - 1);
    }
    g_hostname[sizeof(g_hostname) - 1] = '\0';

    /* Read ephemeral port range */
    read_ephemeral_port_range();

    /* Process /proc/net files */
    if (process_proc_file("/proc/net/tcp", 0, 1) != 0) {
        exit_code = 1;
    }
    if (process_proc_file("/proc/net/tcp6", 1, 1) != 0) {
        exit_code = 1;
    }
    if (process_proc_file("/proc/net/udp", 0, 0) != 0) {
        exit_code = 1;
    }
    if (process_proc_file("/proc/net/udp6", 1, 0) != 0) {
        exit_code = 1;
    }

    /* Deduplicate and sort */
    deduplicate_connections();

    /* Open output file if specified */
    if (output_path != NULL) {
        output_file = fopen(output_path, "w");
        if (output_file == NULL) {
            fprintf(stderr, "gatherd: error: cannot open output file '%s': %s\n",
                    output_path, strerror(errno));
            return 1;
        }
    } else {
        output_file = stdout;
    }

    /* Output results */
    if (json_mode) {
        output_json(output_file);
    } else {
        output_text(output_file);
    }

    /* Clean up */
    if (output_path != NULL && output_file != NULL) {
        if (fclose(output_file) != 0) {
            fprintf(stderr, "gatherd: error: failed to close output file: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    return exit_code;
}

