#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>

// =============================================================================
// CONFIGURATION CONSTANTS
// =============================================================================

#define MAX_PATH_LEN 1024
#define MAX_HEADER_LEN 8192
#define MAX_BODY_SIZE (10 * 1024 * 1024)  // 10MB max body
#define MAX_CONNECTIONS 1000
#define MAX_CONNECTIONS_PER_IP 50
#define SOCKET_TIMEOUT_SEC 30
#define REQUEST_BUFFER_SIZE 8192

// =============================================================================
// GLOBAL STATE
// =============================================================================

// Global variable to store the directory path
char *files_directory = NULL;
char files_directory_realpath[PATH_MAX] = {0};  // Canonicalized path

// Connection tracking
static int active_connections = 0;

// CRC32 table for gzip footer
static uint32_t crc_table[256];

// Initialize CRC32 table
void init_crc_table() {
    for (int i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            if (c & 1)
                c = 0xEDB88320 ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc_table[i] = c;
    }
}

// Calculate CRC32 for a buffer
uint32_t calc_crc32(uint32_t crc, const unsigned char *buf, size_t len) {
    crc = ~crc;
    while (len--) {
        crc = crc_table[(crc ^ *buf) & 0xFF] ^ (crc >> 8);
        buf++;
    }
    return ~crc;
}

// Function to create a basic gzip file in memory
// This creates the simplest possible gzip format without compression
// Returns the size of the gzipped data
unsigned long simple_gzip(char* dest, const char* source, unsigned long source_len) {
    unsigned char *d = (unsigned char*)dest;
    const unsigned char *s = (const unsigned char*)source;
    
    // Initialize CRC table if not done yet
    static int crc_initialized = 0;
    if (!crc_initialized) {
        init_crc_table();
        crc_initialized = 1;
    }
    
    // Calculate CRC32 and length
    uint32_t crc = calc_crc32(0, s, source_len);
    uint32_t len = source_len;
    
    // Gzip header (10 bytes)
    // Magic number (ID1, ID2)
    *d++ = 0x1f;
    *d++ = 0x8b;
    // Compression method (8 = deflate)
    *d++ = 8;
    // Flags (0 = no extra fields)
    *d++ = 0;
    // Modification time (4 bytes, set to 0)
    *d++ = 0;
    *d++ = 0;
    *d++ = 0;
    *d++ = 0;
    // Extra flags (2 = max compression)
    *d++ = 2;
    // Operating system (255 = unknown)
    *d++ = 255;
    
    // Store uncompressed data
    // In a real implementation, this is where deflate compressed data would go
    // For this simple implementation, we're storing uncompressed data with minimal headers
    
    // Add a stored block header
    // 1 byte: last block (1) + type (00 = stored)
    *d++ = 0x01;
    // 2 bytes: length
    *d++ = len & 0xff;
    *d++ = (len >> 8) & 0xff;
    // 2 bytes: one's complement of length
    *d++ = (~len) & 0xff;
    *d++ = (~len >> 8) & 0xff;
    
    // Copy the data
    memcpy(d, s, len);
    d += len;
    
    // Gzip footer (8 bytes)
    // CRC32 (4 bytes)
    *d++ = crc & 0xff;
    *d++ = (crc >> 8) & 0xff;
    *d++ = (crc >> 16) & 0xff;
    *d++ = (crc >> 24) & 0xff;
    
    // Input size modulo 2^32 (4 bytes)
    *d++ = len & 0xff;
    *d++ = (len >> 8) & 0xff;
    *d++ = (len >> 16) & 0xff;
    *d++ = (len >> 24) & 0xff;
    
    // Return total size
    return (d - (unsigned char*)dest);
}

// =============================================================================
// SECURITY FUNCTIONS
// =============================================================================

/**
 * Validate a file path to prevent path traversal attacks.
 *
 * Security measures:
 * 1. Check for null bytes (can truncate strings)
 * 2. Canonicalize path using realpath()
 * 3. Verify the resolved path starts with the document root
 *
 * @param filename The requested filename (after /files/ prefix)
 * @param resolved_path Output buffer for the safe, resolved path
 * @param resolved_size Size of the resolved_path buffer
 * @return 1 if path is safe, 0 if path traversal detected
 */
int validate_file_path(const char *filename, char *resolved_path, size_t resolved_size) {
    // Check for null pointer
    if (filename == NULL || resolved_path == NULL || files_directory_realpath[0] == '\0') {
        return 0;
    }

    // Security check 1: Reject null bytes in filename (null byte injection)
    if (memchr(filename, '\0', strlen(filename)) != filename + strlen(filename)) {
        printf("[SECURITY] Null byte injection attempt detected\n");
        return 0;
    }

    // Security check 2: Reject obviously malicious patterns early
    // This is defense-in-depth; realpath() is the authoritative check
    if (strstr(filename, "..") != NULL) {
        printf("[SECURITY] Path traversal pattern '..' detected in: %s\n", filename);
        return 0;
    }

    // Security check 3: Reject absolute paths
    if (filename[0] == '/') {
        printf("[SECURITY] Absolute path rejected: %s\n", filename);
        return 0;
    }

    // Build the full path
    char full_path[PATH_MAX];
    int written = snprintf(full_path, sizeof(full_path), "%s/%s",
                           files_directory_realpath, filename);

    // Check for truncation
    if (written < 0 || (size_t)written >= sizeof(full_path)) {
        printf("[SECURITY] Path too long: %s\n", filename);
        return 0;
    }

    // Security check 4: Canonicalize the path using realpath()
    // This resolves all symlinks, . and .. components
    char *real = realpath(full_path, resolved_path);

    // For file creation (POST), the file might not exist yet
    // In that case, we validate the directory instead
    if (real == NULL && errno == ENOENT) {
        // Extract directory part and validate it exists
        char dir_path[PATH_MAX];
        strncpy(dir_path, full_path, sizeof(dir_path) - 1);
        dir_path[sizeof(dir_path) - 1] = '\0';

        // Find last slash to get directory
        char *last_slash = strrchr(dir_path, '/');
        if (last_slash != NULL) {
            *last_slash = '\0';

            char resolved_dir[PATH_MAX];
            if (realpath(dir_path, resolved_dir) == NULL) {
                printf("[SECURITY] Directory does not exist: %s\n", dir_path);
                return 0;
            }

            // Verify directory is within document root
            size_t root_len = strlen(files_directory_realpath);
            if (strncmp(resolved_dir, files_directory_realpath, root_len) != 0) {
                printf("[SECURITY] Directory traversal detected: %s resolves outside root\n", filename);
                return 0;
            }

            // Reconstruct the full path with validated directory
            snprintf(resolved_path, resolved_size, "%s/%s",
                     resolved_dir, last_slash + 1 - dir_path + full_path);

            // One more check on the final filename component
            const char *final_name = last_slash + 1 - dir_path + full_path;
            if (strchr(final_name, '/') != NULL || strcmp(final_name, "..") == 0) {
                printf("[SECURITY] Invalid filename component: %s\n", final_name);
                return 0;
            }

            // Copy the intended path for file creation
            snprintf(resolved_path, resolved_size, "%s/%s", resolved_dir,
                     filename + (last_slash - dir_path) + 1);

            return 1;
        }
        return 0;
    }

    if (real == NULL) {
        // File doesn't exist (for GET requests, this will be a 404)
        // But we still need to prevent path traversal attempts
        printf("[SECURITY] realpath() failed for: %s (errno: %d)\n", full_path, errno);
        return 0;
    }

    // Security check 5: Verify the resolved path is within the document root
    size_t root_len = strlen(files_directory_realpath);
    if (strncmp(resolved_path, files_directory_realpath, root_len) != 0) {
        printf("[SECURITY] Path traversal detected: %s resolves to %s (outside root %s)\n",
               filename, resolved_path, files_directory_realpath);
        return 0;
    }

    // Security check 6: Ensure there's a path separator after the root
    // This prevents accessing /var/www/html-secret when root is /var/www/html
    if (resolved_path[root_len] != '\0' && resolved_path[root_len] != '/') {
        printf("[SECURITY] Path escapes root via prefix match: %s\n", resolved_path);
        return 0;
    }

    return 1;
}

/**
 * Check if a string contains only safe characters for a URL path.
 * Allowed: alphanumeric, hyphen, underscore, dot, forward slash
 *
 * @param path The path to validate
 * @return 1 if safe, 0 if contains dangerous characters
 */
int is_safe_path_chars(const char *path) {
    if (path == NULL) return 0;

    for (const char *p = path; *p != '\0'; p++) {
        char c = *p;
        // Allow: A-Z, a-z, 0-9, -, _, ., /
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') ||
              c == '-' || c == '_' || c == '.' || c == '/')) {
            return 0;
        }
    }
    return 1;
}

/**
 * Validate HTTP method.
 * Only allow GET, POST, HEAD methods.
 *
 * @param request The raw HTTP request
 * @return 1 if valid method, 0 otherwise
 */
int validate_http_method(const char *request) {
    if (request == NULL) return 0;

    // Whitelist of allowed methods
    if (strncmp(request, "GET ", 4) == 0) return 1;
    if (strncmp(request, "POST ", 5) == 0) return 1;
    if (strncmp(request, "HEAD ", 5) == 0) return 1;

    return 0;
}

/**
 * Set socket timeouts to prevent slowloris attacks.
 *
 * @param sockfd The socket file descriptor
 * @param timeout_sec Timeout in seconds
 * @return 0 on success, -1 on error
 */
int set_socket_timeout(int sockfd, int timeout_sec) {
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        return -1;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_SNDTIMEO");
        return -1;
    }

    return 0;
}

// =============================================================================
// HTTP PARSING FUNCTIONS
// =============================================================================

// Function to extract the path from an HTTP request
char* extract_path(char* request) {
    static char path[1024];
    
    // Initialize path buffer
    memset(path, 0, sizeof(path));
    
    // Check if this is a GET or POST request
    if (strncmp(request, "GET ", 4) == 0) {
        // Find the end of the path (marked by space before HTTP version)
        char* path_end = strchr(request + 4, ' ');
        if (path_end) {
            // Calculate the path length
            int path_length = path_end - (request + 4);
            // Extract the path
            strncpy(path, request + 4, path_length);
            path[path_length] = '\0';
        }
    } else if (strncmp(request, "POST ", 5) == 0) {
        // Find the end of the path (marked by space before HTTP version)
        char* path_end = strchr(request + 5, ' ');
        if (path_end) {
            // Calculate the path length
            int path_length = path_end - (request + 5);
            // Extract the path
            strncpy(path, request + 5, path_length);
            path[path_length] = '\0';
        }
    }
    
    return path;
}

// Function to determine if the request is a POST request
int is_post_request(char* request) {
    return strncmp(request, "POST ", 5) == 0;
}

// Function to check if a path starts with a specific prefix
int path_starts_with(const char* path, const char* prefix) {
    return strncmp(path, prefix, strlen(prefix)) == 0;
}

// Function to extract the echo string from path (with bounds checking)
char* extract_echo_string(const char* path) {
    static char echo_str[MAX_PATH_LEN];

    // Skip "/echo/" prefix
    const char* start = path + 6; // 6 is the length of "/echo/"

    // Copy the rest of the path with bounds checking
    size_t len = strlen(start);
    if (len >= sizeof(echo_str)) {
        len = sizeof(echo_str) - 1;
    }
    strncpy(echo_str, start, len);
    echo_str[len] = '\0';

    return echo_str;
}

// Function to extract the filename from a /files/ path (with bounds checking)
char* extract_filename(const char* path) {
    static char filename[MAX_PATH_LEN];

    // Skip "/files/" prefix
    const char* start = path + 7; // 7 is the length of "/files/"

    // Copy the rest of the path with bounds checking
    size_t len = strlen(start);
    if (len >= sizeof(filename)) {
        len = sizeof(filename) - 1;
    }
    strncpy(filename, start, len);
    filename[len] = '\0';

    return filename;
}

// Function to extract a header value from an HTTP request (with bounds checking)
char* extract_header_value(const char* request, const char* header_name) {
    static char value[MAX_PATH_LEN];
    memset(value, 0, sizeof(value));

    if (request == NULL || header_name == NULL) {
        return value;
    }

    // Create the header string to search for (case-insensitive)
    char search_header[256];
    int written = snprintf(search_header, sizeof(search_header), "\r\n%s: ", header_name);
    if (written < 0 || (size_t)written >= sizeof(search_header)) {
        return value;  // Header name too long
    }

    // Convert search header to lowercase for case-insensitive search
    for (int i = 0; search_header[i]; i++) {
        search_header[i] = tolower(search_header[i]);
    }

    // Create lowercase version of request for searching
    char* lower_request = strdup(request);
    if (lower_request == NULL) {
        return value;  // Memory allocation failed
    }

    for (int i = 0; lower_request[i]; i++) {
        lower_request[i] = tolower(lower_request[i]);
    }

    // Look for the header
    char* header_pos = strstr(lower_request, search_header);
    if (header_pos) {
        // Calculate the position in the original request
        size_t offset = header_pos - lower_request;

        // Get position after the header name and colon
        const char* value_start = request + offset + strlen(search_header);

        // Find the end of the value (marked by CRLF)
        const char* value_end = strstr(value_start, "\r\n");
        if (value_end) {
            // Calculate the value length with bounds checking
            size_t value_length = value_end - value_start;
            if (value_length >= sizeof(value)) {
                value_length = sizeof(value) - 1;
            }

            // Extract the value
            strncpy(value, value_start, value_length);
            value[value_length] = '\0';
        }
    }

    // Free the temporary lowercase request
    free(lower_request);

    return value;
}

// Function to check if client supports gzip encoding
int client_supports_gzip(const char* request) {
    char* accept_encoding = extract_header_value(request, "Accept-Encoding");
    
    // Check if gzip is in the Accept-Encoding header
    if (strstr(accept_encoding, "gzip") != NULL) {
        return 1;
    }
    
    return 0;
}

// Function to extract the request body from an HTTP request
char* extract_request_body(char* request, int* body_length) {
    char* body_start = strstr(request, "\r\n\r\n");
    if (body_start) {
        body_start += 4; // Skip the \r\n\r\n
        
        // Get the Content-Length header
        char* content_length_str = extract_header_value(request, "Content-Length");
        if (content_length_str[0] != '\0') {
            *body_length = atoi(content_length_str);
            return body_start;
        }
    }
    
    *body_length = 0;
    return NULL;
}

// Handler for SIGCHLD to reap child processes and track connection count
void handle_sigchld(int sig) {
    (void)sig;  // Suppress unused parameter warning

    // Reap all dead processes and decrement connection counter
    int saved_errno = errno;  // Save errno, as waitpid may modify it
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        if (active_connections > 0) {
            active_connections--;
        }
    }
    errno = saved_errno;  // Restore errno
}

// Function to handle a client connection
void handle_client(int client_fd) {
    // SECURITY: Set socket timeouts to prevent slowloris attacks
    set_socket_timeout(client_fd, SOCKET_TIMEOUT_SEC);

    // Buffer to store the received HTTP request
    char buffer[REQUEST_BUFFER_SIZE] = {0};

    // Read the HTTP request
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("PID %d: [SECURITY] Connection timeout - possible slowloris attack\n", getpid());
        } else {
            printf("PID %d: Failed to read request (errno: %d)\n", getpid(), errno);
        }
        close(client_fd);
        exit(0);
    }

    buffer[bytes_read] = '\0';
    printf("Received request (%zd bytes):\n%s\n", bytes_read, buffer);

    // SECURITY: Validate HTTP method (whitelist approach)
    if (!validate_http_method(buffer)) {
        const char *response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
        printf("PID %d: [SECURITY] Invalid HTTP method rejected\n", getpid());
        close(client_fd);
        exit(0);
    }

    // Extract the path from the request
    char* path = extract_path(buffer);
    printf("Extracted path: %s\n", path);

    // SECURITY: Validate path contains only safe characters
    if (!is_safe_path_chars(path)) {
        const char *response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
        printf("PID %d: [SECURITY] Invalid characters in path: %s\n", getpid(), path);
        close(client_fd);
        exit(0);
    }

    // Check if client supports gzip
    int supports_gzip = client_supports_gzip(buffer);
    printf("Client supports gzip: %s\n", supports_gzip ? "Yes" : "No");

    // Check if it's a POST request
    int is_post = is_post_request(buffer);
    
    // Determine the appropriate response based on the path
    if (strcmp(path, "/") == 0) {
        // Root path - return 200 OK
        const char *response = "HTTP/1.1 200 OK\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
        printf("PID %d: Sent 200 OK response for root path\n", getpid());
    } else if (path_starts_with(path, "/echo/")) {
        // Echo endpoint
        char* echo_str = extract_echo_string(path);
        int echo_len = strlen(echo_str);
        
        if (supports_gzip) {
            // Prepare buffers for compression - allocate enough space
            // Simple gzip adds about 20 bytes of overhead
            char* compressed_data = malloc(echo_len + 32);
            
            if (compressed_data == NULL) {
                // Failed to allocate memory
                const char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                send(client_fd, response, strlen(response), 0);
                printf("PID %d: Failed to allocate memory for compression\n", getpid());
            } else {
                // Compress the echo string
                unsigned long compressed_size = simple_gzip(compressed_data, echo_str, echo_len);
                
                if (compressed_size > 0) {
                    // Create response with Content-Type, Content-Encoding, and correct Content-Length headers
                    char response_headers[512];
                    snprintf(response_headers, sizeof(response_headers),
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: %lu\r\n\r\n",
                            compressed_size);

                    // Send headers
                    send(client_fd, response_headers, strlen(response_headers), 0);

                    // Send compressed data
                    send(client_fd, compressed_data, compressed_size, 0);

                    printf("PID %d: Sent gzip-compressed echo response with string: %s (original size: %d, compressed: %lu)\n",
                           getpid(), echo_str, echo_len, compressed_size);
                } else {
                    // Compression failed, fallback to uncompressed
                    char response_headers[512];
                    snprintf(response_headers, sizeof(response_headers),
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n",
                            echo_len);
                    send(client_fd, response_headers, strlen(response_headers), 0);
                    send(client_fd, echo_str, echo_len, 0);
                    printf("PID %d: Compression failed, sent uncompressed echo response: %s\n", getpid(), echo_str);
                }

                // Free the compressed data buffer
                free(compressed_data);
            }
        } else {
            // Standard response without compression
            char response_headers[512];
            snprintf(response_headers, sizeof(response_headers),
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n",
                    echo_len);
            send(client_fd, response_headers, strlen(response_headers), 0);
            send(client_fd, echo_str, echo_len, 0);
            printf("PID %d: Sent uncompressed echo response: %s\n", getpid(), echo_str);
        }
    } else if (strcmp(path, "/user-agent") == 0) {
        // User-Agent endpoint
        char* user_agent = extract_header_value(buffer, "User-Agent");
        int user_agent_len = strlen(user_agent);
        
        if (supports_gzip) {
            // Prepare buffers for compression
            char* compressed_data = malloc(user_agent_len + 32);
            
            if (compressed_data == NULL) {
                // Failed to allocate memory
                const char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                send(client_fd, response, strlen(response), 0);
                printf("PID %d: Failed to allocate memory for compression\n", getpid());
            } else {
                // Compress the user agent string
                unsigned long compressed_size = simple_gzip(compressed_data, user_agent, user_agent_len);
                
                if (compressed_size > 0) {
                    // Create response with Content-Type, Content-Encoding, and correct Content-Length headers
                    char response_headers[512];
                    snprintf(response_headers, sizeof(response_headers),
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: %lu\r\n\r\n",
                            compressed_size);

                    // Send headers
                    send(client_fd, response_headers, strlen(response_headers), 0);

                    // Send compressed data
                    send(client_fd, compressed_data, compressed_size, 0);

                    printf("PID %d: Sent gzip-compressed user-agent response: %s (original size: %d, compressed: %lu)\n",
                           getpid(), user_agent, user_agent_len, compressed_size);
                } else {
                    // Compression failed, fallback to uncompressed
                    char response_headers[512];
                    snprintf(response_headers, sizeof(response_headers),
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n",
                            user_agent_len);
                    send(client_fd, response_headers, strlen(response_headers), 0);
                    send(client_fd, user_agent, user_agent_len, 0);
                    printf("PID %d: Compression failed, sent uncompressed user-agent response: %s\n", getpid(), user_agent);
                }

                // Free the compressed data buffer
                free(compressed_data);
            }
        } else {
            // Standard response without compression
            char response_headers[512];
            snprintf(response_headers, sizeof(response_headers),
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n",
                    user_agent_len);
            send(client_fd, response_headers, strlen(response_headers), 0);
            send(client_fd, user_agent, user_agent_len, 0);
            printf("PID %d: Sent user-agent response: %s\n", getpid(), user_agent);
        }
    } else if (path_starts_with(path, "/files/") && files_directory != NULL) {
        // Files endpoint
        char* filename = extract_filename(path);

        // SECURITY: Validate the file path to prevent path traversal attacks
        char filepath[PATH_MAX];
        if (!validate_file_path(filename, filepath, sizeof(filepath))) {
            // Path traversal attempt or invalid path - return 403 Forbidden
            const char *response = "HTTP/1.1 403 Forbidden\r\n\r\n";
            send(client_fd, response, strlen(response), 0);
            printf("PID %d: [SECURITY] Blocked path traversal attempt: %s\n", getpid(), filename);
            close(client_fd);
            exit(0);
        }

        if (is_post) {
            // POST request - create a new file
            int body_length = 0;
            char* body = extract_request_body(buffer, &body_length);

            // SECURITY: Validate body size
            if (body_length > MAX_BODY_SIZE) {
                const char *response = "HTTP/1.1 413 Payload Too Large\r\n\r\n";
                send(client_fd, response, strlen(response), 0);
                printf("PID %d: [SECURITY] Request body too large: %d bytes\n", getpid(), body_length);
                close(client_fd);
                exit(0);
            }

            if (body && body_length > 0) {
                // Open file for writing
                int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd == -1) {
                    // Failed to create file
                    const char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                    send(client_fd, response, strlen(response), 0);
                    printf("PID %d: Failed to create file: %s (errno: %d)\n", getpid(), filename, errno);
                } else {
                    // Write the request body to the file
                    write(fd, body, body_length);
                    close(fd);

                    // Return 201 Created
                    const char *response = "HTTP/1.1 201 Created\r\n\r\n";
                    send(client_fd, response, strlen(response), 0);
                    printf("PID %d: Created file: %s (size: %d bytes)\n", getpid(), filename, body_length);
                }
            } else {
                // Bad request - missing or empty body
                const char *response = "HTTP/1.1 400 Bad Request\r\n\r\n";
                send(client_fd, response, strlen(response), 0);
                printf("PID %d: Bad request - missing or empty body\n", getpid());
            }
        } else {
            // GET request - read file
            int fd = open(filepath, O_RDONLY);
            if (fd == -1) {
                // File not found - return 404
                const char *response = "HTTP/1.1 404 Not Found\r\n\r\n";
                send(client_fd, response, strlen(response), 0);
                printf("PID %d: Sent 404 Not Found response for file: %s\n", getpid(), filename);
            } else {
                // Get file size
                struct stat file_stat;
                fstat(fd, &file_stat);
                off_t file_size = file_stat.st_size;
                
                if (supports_gzip && file_size > 0) {
                    // Read the file content into memory
                    char* file_content = malloc(file_size);
                    if (file_content == NULL) {
                        // Failed to allocate memory
                        const char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                        send(client_fd, response, strlen(response), 0);
                        printf("PID %d: Failed to allocate memory for file: %s\n", getpid(), filename);
                        close(fd);
                        return;
                    }
                    
                    // Read file content
                    ssize_t bytes_read = read(fd, file_content, file_size);
                    close(fd);
                    
                    if (bytes_read != file_size) {
                        // Failed to read the entire file
                        const char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                        send(client_fd, response, strlen(response), 0);
                        printf("PID %d: Failed to read entire file: %s\n", getpid(), filename);
                        free(file_content);
                        return;
                    }
                    
                    // Prepare buffers for compression
                    char* compressed_data = malloc(file_size + 32);
                    
                    if (compressed_data == NULL) {
                        // Failed to allocate memory for compression
                        const char *response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                        send(client_fd, response, strlen(response), 0);
                        printf("PID %d: Failed to allocate memory for compression\n", getpid());
                        free(file_content);
                        return;
                    }
                    
                    // Compress the file content
                    unsigned long compressed_size = simple_gzip(compressed_data, file_content, file_size);
                    
                    if (compressed_size > 0) {
                        // Create response with Content-Type, Content-Encoding, and correct Content-Length headers
                        char response_headers[512];
                        snprintf(response_headers, sizeof(response_headers),
                                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Encoding: gzip\r\nContent-Length: %lu\r\n\r\n",
                                compressed_size);

                        // Send headers
                        send(client_fd, response_headers, strlen(response_headers), 0);

                        // Send compressed data
                        send(client_fd, compressed_data, compressed_size, 0);

                        printf("PID %d: Sent gzip-compressed file: %s (original size: %ld, compressed: %lu)\n",
                               getpid(), filename, file_size, compressed_size);
                    } else {
                        // Compression failed, fallback to uncompressed
                        char response_headers[512];
                        snprintf(response_headers, sizeof(response_headers),
                                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %ld\r\n\r\n",
                                file_size);

                        // Send headers
                        send(client_fd, response_headers, strlen(response_headers), 0);

                        // Send file content
                        send(client_fd, file_content, file_size, 0);

                        printf("PID %d: Compression failed, sent uncompressed file: %s (size: %ld bytes)\n",
                               getpid(), filename, file_size);
                    }

                    // Free memory
                    free(file_content);
                    free(compressed_data);
                } else {
                    // Standard response without compression
                    char headers[512];
                    snprintf(headers, sizeof(headers),
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %ld\r\n\r\n",
                            file_size);

                    // Send headers
                    send(client_fd, headers, strlen(headers), 0);

                    // Send file content
                    char file_buffer[4096];
                    ssize_t bytes_read;

                    while ((bytes_read = read(fd, file_buffer, sizeof(file_buffer))) > 0) {
                        send(client_fd, file_buffer, bytes_read, 0);
                    }

                    // Close file
                    close(fd);

                    printf("PID %d: Sent file: %s (size: %ld bytes)\n", getpid(), filename, file_size);
                }
            }
        }
    } else {
        // Any other path - return 404 Not Found
        const char *response = "HTTP/1.1 404 Not Found\r\n\r\n";
        send(client_fd, response, strlen(response), 0);
        printf("PID %d: Sent 404 Not Found response\n", getpid());
    }
    
    // Close the client socket
    close(client_fd);
    exit(0);  // Child process exits after handling the request
}

int main(int argc, char *argv[]) {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("===========================================\n");
    printf("HTTP Server v1.1 (Security Hardened)\n");
    printf("===========================================\n");
    printf("Logs from your program will appear here!\n");

    // Parse command line arguments for --directory flag
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--directory") == 0 && i + 1 < argc) {
            files_directory = argv[i + 1];

            // SECURITY: Canonicalize the document root path at startup
            if (realpath(files_directory, files_directory_realpath) == NULL) {
                printf("ERROR: Cannot resolve directory path: %s (errno: %d)\n",
                       files_directory, errno);
                printf("Make sure the directory exists and is accessible.\n");
                return 1;
            }

            printf("Document root: %s\n", files_directory);
            printf("Resolved path: %s\n", files_directory_realpath);
            break;
        }
    }

    // Print security configuration
    printf("\n--- Security Configuration ---\n");
    printf("Max connections: %d\n", MAX_CONNECTIONS);
    printf("Socket timeout: %d seconds\n", SOCKET_TIMEOUT_SEC);
    printf("Max request size: %d bytes\n", REQUEST_BUFFER_SIZE);
    printf("Max body size: %d bytes\n", MAX_BODY_SIZE);
    printf("Path traversal protection: ENABLED\n");
    printf("Method whitelist: GET, POST, HEAD\n");
    printf("------------------------------\n\n");

    // Set up signal handler for SIGCHLD to reap zombie processes
    struct sigaction sa;
    sa.sa_handler = handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    int server_fd, client_fd;
    socklen_t client_addr_len;
    struct sockaddr_in client_addr;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        printf("Socket creation failed: %s...\n", strerror(errno));
        return 1;
    }

    // Since the tester restarts your program quite often, setting SO_REUSEADDR
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        printf("SO_REUSEADDR failed: %s \n", strerror(errno));
        return 1;
    }

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(4221),
        .sin_addr = { htonl(INADDR_ANY) },
    };

    if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
        printf("Bind failed: %s \n", strerror(errno));
        return 1;
    }

    // Increased backlog for better connection handling
    int connection_backlog = 128;
    if (listen(server_fd, connection_backlog) != 0) {
        printf("Listen failed: %s \n", strerror(errno));
        return 1;
    }

    printf("Server started on port 4221. Waiting for connections...\n");

    while (1) {
        // SECURITY: Check connection limit before accepting
        if (active_connections >= MAX_CONNECTIONS) {
            printf("[SECURITY] Max connections (%d) reached, rejecting new connection\n",
                   MAX_CONNECTIONS);
            // Brief sleep to prevent busy-loop
            usleep(10000);  // 10ms
            continue;
        }

        client_addr_len = sizeof(client_addr);

        client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len);
        if (client_fd < 0) {
            if (errno != EINTR) {  // Ignore interrupted system calls
                printf("Accept failed: %s \n", strerror(errno));
            }
            continue;
        }

        // Track active connections
        active_connections++;
        printf("Client connected (active: %d) - spawning child process\n", active_connections);

        // Fork a child process to handle the client
        pid_t pid = fork();

        if (pid < 0) {
            // Fork failed
            printf("Fork failed: %s\n", strerror(errno));
            close(client_fd);
            active_connections--;
            continue;
        } else if (pid == 0) {
            // Child process
            close(server_fd);  // Child doesn't need the server socket
            handle_client(client_fd);
            // Child process exits in handle_client function
        } else {
            // Parent process
            close(client_fd);  // Parent doesn't need the client socket
            printf("Created child process with PID: %d\n", pid);
            // Note: active_connections will be decremented by SIGCHLD handler
            // Parent continues to accept new connections
        }
    }
    
    // Close the server socket
    close(server_fd);

    return 0;
}