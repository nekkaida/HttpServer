#ifndef HTTP_SERVER_HTTP_PARSER_H
#define HTTP_SERVER_HTTP_PARSER_H

/**
 * HTTP Parser Module
 *
 * Provides HTTP request parsing functions for:
 * - Extracting request path
 * - Extracting headers
 * - Extracting request body
 * - Determining request method
 */

#include "../include/common.h"

// =============================================================================
// REQUEST PARSING
// =============================================================================

/**
 * Extract the path from an HTTP request.
 *
 * @param request The raw HTTP request string
 * @return Pointer to static buffer containing the path (do not free)
 */
char* http_extract_path(const char *request);

/**
 * Extract a header value from an HTTP request (case-insensitive).
 *
 * @param request The raw HTTP request string
 * @param header_name The header name to search for
 * @return Pointer to static buffer containing the value (do not free)
 */
char* http_extract_header(const char *request, const char *header_name);

/**
 * Extract the request body from an HTTP request.
 *
 * @param request The raw HTTP request string
 * @param body_length Output: the length of the body
 * @return Pointer to the body within the request buffer, or NULL if no body
 */
char* http_extract_body(char *request, int *body_length);

// =============================================================================
// REQUEST TYPE DETECTION
// =============================================================================

/**
 * Check if the request is a POST request.
 *
 * @param request The raw HTTP request string
 * @return 1 if POST, 0 otherwise
 */
int http_is_post_request(const char *request);

/**
 * Check if the request is a GET request.
 *
 * @param request The raw HTTP request string
 * @return 1 if GET, 0 otherwise
 */
int http_is_get_request(const char *request);

/**
 * Get the HTTP method type from request.
 *
 * @param request The raw HTTP request string
 * @return http_method_t enum value
 */
http_method_t http_get_method(const char *request);

// =============================================================================
// PATH HELPERS
// =============================================================================

/**
 * Check if a path starts with a specific prefix.
 *
 * @param path The path to check
 * @param prefix The prefix to match
 * @return 1 if path starts with prefix, 0 otherwise
 */
int http_path_starts_with(const char *path, const char *prefix);

/**
 * Extract the string after /echo/ in the path.
 *
 * @param path The request path
 * @return Pointer to static buffer containing the echo string (do not free)
 */
char* http_extract_echo_string(const char *path);

/**
 * Extract the filename after /files/ in the path.
 *
 * @param path The request path
 * @return Pointer to static buffer containing the filename (do not free)
 */
char* http_extract_filename(const char *path);

// =============================================================================
// COMPRESSION DETECTION
// =============================================================================

/**
 * Check if client supports gzip encoding.
 *
 * @param request The raw HTTP request string
 * @return 1 if gzip supported, 0 otherwise
 */
int http_client_supports_gzip(const char *request);

// =============================================================================
// HTTP/1.1 COMPLIANCE
// =============================================================================

/**
 * Generate an HTTP-date formatted timestamp.
 * Format: "Day, DD Mon YYYY HH:MM:SS GMT"
 *
 * @param buffer Output buffer (must be at least 32 bytes)
 * @param buffer_size Size of the output buffer
 * @return Pointer to buffer on success, NULL on error
 */
char* http_format_date(char *buffer, size_t buffer_size);

/**
 * Validate Host header presence (required in HTTP/1.1).
 *
 * @param request The raw HTTP request string
 * @return 1 if valid Host header present, 0 otherwise
 */
int http_validate_host_header(const char *request);

/**
 * Get HTTP version from request.
 *
 * @param request The raw HTTP request string
 * @return HTTP version (10 for 1.0, 11 for 1.1, 0 for invalid)
 */
int http_get_version(const char *request);

#endif // HTTP_SERVER_HTTP_PARSER_H
