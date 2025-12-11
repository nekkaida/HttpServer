#ifndef HTTP_SERVER_HANDLERS_H
#define HTTP_SERVER_HANDLERS_H

/**
 * Request Handlers Module
 *
 * Provides HTTP request handlers for different endpoints:
 * - Root (/)
 * - Echo (/echo/*)
 * - User-Agent (/user-agent)
 * - Files (/files/*)
 */

#include "../include/common.h"

// =============================================================================
// HANDLER CONTEXT
// =============================================================================

/**
 * Context passed to all request handlers.
 */
typedef struct {
    int client_fd;              // Client socket
    const char *request;        // Raw HTTP request
    const char *path;           // Extracted path
    int supports_gzip;          // Client supports gzip?
    const char *document_root;  // Document root (for file serving)
    const char *client_ip;      // Client IP address
} handler_context_t;

// =============================================================================
// ENDPOINT HANDLERS
// =============================================================================

/**
 * Handle root path request (/).
 *
 * @param ctx Handler context
 */
void handle_root(const handler_context_t *ctx);

/**
 * Handle health check request (/health).
 * Returns server status for load balancer health checks.
 *
 * @param ctx Handler context
 */
void handle_health(const handler_context_t *ctx);

/**
 * Handle echo request (/echo/*).
 *
 * @param ctx Handler context
 */
void handle_echo(const handler_context_t *ctx);

/**
 * Handle user-agent request (/user-agent).
 *
 * @param ctx Handler context
 */
void handle_user_agent(const handler_context_t *ctx);

/**
 * Handle file request (/files/*).
 * Supports both GET (download) and POST (upload).
 *
 * @param ctx Handler context
 * @param is_post 1 for POST request, 0 for GET
 */
void handle_files(const handler_context_t *ctx, int is_post);

/**
 * Handle 404 Not Found response.
 *
 * @param ctx Handler context
 */
void handle_not_found(const handler_context_t *ctx);

// =============================================================================
// RESPONSE HELPERS
// =============================================================================

/**
 * Send a simple HTTP response with no body.
 *
 * @param client_fd Client socket
 * @param status_line Complete status line with CRLF (e.g., "HTTP/1.1 200 OK\r\n\r\n")
 */
void send_status_response(int client_fd, const char *status_line);

/**
 * Send an HTTP response with text body.
 * Optionally compresses with gzip if supported.
 *
 * @param client_fd Client socket
 * @param body Response body
 * @param body_len Length of body
 * @param content_type Content-Type header value
 * @param use_gzip Whether to use gzip compression
 */
void send_text_response(int client_fd, const char *body, size_t body_len,
                        const char *content_type, int use_gzip);

/**
 * Send an HTTP file response.
 * Reads file and sends with optional gzip compression.
 *
 * @param client_fd Client socket
 * @param filepath Path to file
 * @param use_gzip Whether to use gzip compression
 * @return 0 on success, -1 on error
 */
int send_file_response(int client_fd, const char *filepath, int use_gzip);

#endif // HTTP_SERVER_HANDLERS_H
