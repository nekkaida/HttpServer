#ifndef HTTP_SERVER_SECURITY_H
#define HTTP_SERVER_SECURITY_H

/**
 * Security Module
 *
 * Provides security functions for:
 * - Path traversal prevention
 * - Input validation
 * - Socket timeout configuration
 * - Rate limiting (future)
 */

#include "../include/common.h"

// =============================================================================
// PATH VALIDATION
// =============================================================================

/**
 * Validate a file path to prevent path traversal attacks.
 *
 * Security measures:
 * 1. Check for null bytes (can truncate strings)
 * 2. Reject .. sequences
 * 3. Reject absolute paths
 * 4. Canonicalize path using realpath()
 * 5. Verify the resolved path starts with the document root
 *
 * @param filename The requested filename (after /files/ prefix)
 * @param resolved_path Output buffer for the safe, resolved path
 * @param resolved_size Size of the resolved_path buffer
 * @param document_root The canonical document root path
 * @return 1 if path is safe, 0 if path traversal detected
 */
int validate_file_path(const char *filename, char *resolved_path,
                       size_t resolved_size, const char *document_root);

/**
 * Check if a string contains only safe characters for a URL path.
 * Allowed: alphanumeric, hyphen, underscore, dot, forward slash
 *
 * @param path The path to validate
 * @return 1 if safe, 0 if contains dangerous characters
 */
int is_safe_path_chars(const char *path);

// =============================================================================
// HTTP VALIDATION
// =============================================================================

/**
 * Validate HTTP method against whitelist.
 * Only allows GET, POST, HEAD methods.
 *
 * @param request The raw HTTP request
 * @return 1 if valid method, 0 otherwise
 */
int validate_http_method(const char *request);

// =============================================================================
// SOCKET SECURITY
// =============================================================================

/**
 * Set socket timeouts to prevent slowloris attacks.
 *
 * @param sockfd The socket file descriptor
 * @param timeout_sec Timeout in seconds
 * @return 0 on success, -1 on error
 */
int set_socket_timeout(int sockfd, int timeout_sec);

// =============================================================================
// INITIALIZATION
// =============================================================================

/**
 * Initialize the document root path.
 * Must be called before using validate_file_path().
 *
 * @param path The directory path to use as document root
 * @param resolved_root Output buffer for canonical path (PATH_MAX size)
 * @return 0 on success, -1 on error
 */
int security_init_document_root(const char *path, char *resolved_root);

#endif // HTTP_SERVER_SECURITY_H
