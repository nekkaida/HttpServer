#ifndef HTTP_SERVER_CONFIG_H
#define HTTP_SERVER_CONFIG_H

/**
 * HTTP Server Configuration
 *
 * Central configuration constants for the HTTP server.
 * Modify these values to tune server behavior.
 */

// =============================================================================
// NETWORK CONFIGURATION
// =============================================================================

#define SERVER_PORT 4221
#define CONNECTION_BACKLOG 128

// =============================================================================
// SECURITY LIMITS
// =============================================================================

#define MAX_PATH_LEN 1024
#define MAX_HEADER_LEN 8192
#define MAX_BODY_SIZE (10 * 1024 * 1024)  // 10MB max body
#define MAX_CONNECTIONS 1000
#define MAX_CONNECTIONS_PER_IP 50
#define SOCKET_TIMEOUT_SEC 30
#define REQUEST_BUFFER_SIZE 8192

// =============================================================================
// BUFFER SIZES
// =============================================================================

#define RESPONSE_HEADER_SIZE 512
#define FILE_BUFFER_SIZE 4096

// =============================================================================
// FEATURE FLAGS
// =============================================================================

#define ENABLE_GZIP_COMPRESSION 1
#define ENABLE_ACCESS_LOGGING 1
#define ENABLE_SECURITY_LOGGING 1

#endif // HTTP_SERVER_CONFIG_H
