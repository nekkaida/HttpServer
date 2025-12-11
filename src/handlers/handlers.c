/**
 * Request Handlers Module Implementation
 *
 * Implements HTTP request handlers for all endpoints.
 */

#include "handlers.h"
#include "../http/http_parser.h"
#include "../compression/gzip.h"
#include "../security/security.h"

// =============================================================================
// RESPONSE HELPERS
// =============================================================================

void send_status_response(int client_fd, const char *status_line) {
    send(client_fd, status_line, strlen(status_line), 0);
}

void send_text_response(int client_fd, const char *body, size_t body_len,
                        const char *content_type, int use_gzip) {
    char headers[RESPONSE_HEADER_SIZE];
    char date_buf[64];
    http_format_date(date_buf, sizeof(date_buf));

    if (use_gzip && body_len > 0) {
        // Compress the response
        char *compressed = malloc(body_len + 32);
        if (compressed == NULL) {
            // Fallback to uncompressed
            use_gzip = 0;
        } else {
            unsigned long compressed_size = gzip_compress(compressed, body, body_len);

            if (compressed_size > 0) {
                snprintf(headers, sizeof(headers),
                        "HTTP/1.1 200 OK\r\n"
                        "Date: %s\r\n"
                        "Content-Type: %s\r\n"
                        "Content-Encoding: gzip\r\n"
                        "Content-Length: %lu\r\n\r\n",
                        date_buf, content_type, compressed_size);

                send(client_fd, headers, strlen(headers), 0);
                send(client_fd, compressed, compressed_size, 0);
                free(compressed);
                return;
            }
            free(compressed);
            // Fallback to uncompressed on compression failure
        }
    }

    // Send uncompressed
    snprintf(headers, sizeof(headers),
            "HTTP/1.1 200 OK\r\n"
            "Date: %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n\r\n",
            date_buf, content_type, body_len);

    send(client_fd, headers, strlen(headers), 0);
    if (body_len > 0) {
        send(client_fd, body, body_len, 0);
    }
}

int send_file_response(int client_fd, const char *filepath, int use_gzip) {
    int fd = open(filepath, O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    // Get file size
    struct stat file_stat;
    if (fstat(fd, &file_stat) == -1) {
        close(fd);
        return -1;
    }
    off_t file_size = file_stat.st_size;

    char headers[RESPONSE_HEADER_SIZE];
    char date_buf[64];
    http_format_date(date_buf, sizeof(date_buf));

    if (use_gzip && file_size > 0) {
        // Read entire file for compression
        char *file_content = malloc(file_size);
        if (file_content == NULL) {
            close(fd);
            return -1;
        }

        ssize_t bytes_read = read(fd, file_content, file_size);
        close(fd);

        if (bytes_read != file_size) {
            free(file_content);
            return -1;
        }

        // Compress
        char *compressed = malloc(file_size + 32);
        if (compressed == NULL) {
            free(file_content);
            return -1;
        }

        unsigned long compressed_size = gzip_compress(compressed, file_content, file_size);
        free(file_content);

        if (compressed_size > 0) {
            snprintf(headers, sizeof(headers),
                    "HTTP/1.1 200 OK\r\n"
                    "Date: %s\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Content-Encoding: gzip\r\n"
                    "Content-Length: %lu\r\n\r\n",
                    date_buf, compressed_size);

            send(client_fd, headers, strlen(headers), 0);
            send(client_fd, compressed, compressed_size, 0);
            free(compressed);
            return 0;
        }

        // Compression failed, need to re-open file for uncompressed send
        free(compressed);
        fd = open(filepath, O_RDONLY);
        if (fd == -1) {
            return -1;
        }
    }

    // Send uncompressed
    snprintf(headers, sizeof(headers),
            "HTTP/1.1 200 OK\r\n"
            "Date: %s\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: %ld\r\n\r\n",
            date_buf, (long)file_size);

    send(client_fd, headers, strlen(headers), 0);

    // Stream file content
    char buffer[FILE_BUFFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        send(client_fd, buffer, bytes_read, 0);
    }

    close(fd);
    return 0;
}

// =============================================================================
// ENDPOINT HANDLERS
// =============================================================================

void handle_root(const handler_context_t *ctx) {
    char response[256];
    char date_buf[64];
    http_format_date(date_buf, sizeof(date_buf));

    snprintf(response, sizeof(response),
             "HTTP/1.1 200 OK\r\n"
             "Date: %s\r\n\r\n",
             date_buf);

    send(ctx->client_fd, response, strlen(response), 0);
    LOG_DEBUG("Sent 200 OK for root path");
}

void handle_health(const handler_context_t *ctx) {
    char response[512];
    char date_buf[64];
    http_format_date(date_buf, sizeof(date_buf));

    const char *body = "{\"status\":\"ok\"}";
    size_t body_len = strlen(body);

    snprintf(response, sizeof(response),
             "HTTP/1.1 200 OK\r\n"
             "Date: %s\r\n"
             "Content-Type: application/json\r\n"
             "Cache-Control: no-cache, no-store\r\n"
             "Content-Length: %zu\r\n\r\n"
             "%s",
             date_buf, body_len, body);

    send(ctx->client_fd, response, strlen(response), 0);
    LOG_DEBUG("Sent health check response");
}

void handle_echo(const handler_context_t *ctx) {
    char *echo_str = http_extract_echo_string(ctx->path);
    size_t echo_len = strlen(echo_str);

    send_text_response(ctx->client_fd, echo_str, echo_len, "text/plain",
                       ctx->supports_gzip);

    LOG_DEBUG("Sent echo response: %s", echo_str);
}

void handle_user_agent(const handler_context_t *ctx) {
    char *user_agent = http_extract_header(ctx->request, "User-Agent");
    size_t ua_len = strlen(user_agent);

    send_text_response(ctx->client_fd, user_agent, ua_len, "text/plain",
                       ctx->supports_gzip);

    LOG_DEBUG("Sent user-agent response: %s", user_agent);
}

void handle_files(const handler_context_t *ctx, int is_post) {
    char *filename = http_extract_filename(ctx->path);

    // Validate the file path
    char filepath[PATH_MAX];
    if (!validate_file_path(filename, filepath, sizeof(filepath), ctx->document_root)) {
        send_status_response(ctx->client_fd, HTTP_403_FORBIDDEN);
        LOG_SECURITY("Blocked path traversal attempt: %s", filename);
        return;
    }

    if (is_post) {
        // POST request - create a new file
        int body_length = 0;
        char *body = http_extract_body((char *)ctx->request, &body_length);

        // Validate body size
        if (body_length > MAX_BODY_SIZE) {
            send_status_response(ctx->client_fd, HTTP_413_PAYLOAD_TOO_LARGE);
            LOG_SECURITY("Request body too large: %d bytes", body_length);
            return;
        }

        if (body && body_length > 0) {
            int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd == -1) {
                send_status_response(ctx->client_fd, HTTP_500_INTERNAL_ERROR);
                LOG_ERROR("Failed to create file: %s (errno: %d)", filename, errno);
                return;
            }

            write(fd, body, body_length);
            close(fd);

            send_status_response(ctx->client_fd, HTTP_201_CREATED);
            LOG_DEBUG("Created file: %s (%d bytes)", filename, body_length);
        } else {
            send_status_response(ctx->client_fd, HTTP_400_BAD_REQUEST);
            LOG_DEBUG("Bad request - missing or empty body");
        }
    } else {
        // GET request - serve file
        if (send_file_response(ctx->client_fd, filepath, ctx->supports_gzip) < 0) {
            send_status_response(ctx->client_fd, HTTP_404_NOT_FOUND);
            LOG_DEBUG("File not found: %s", filename);
        } else {
            LOG_DEBUG("Sent file: %s", filename);
        }
    }
}

void handle_not_found(const handler_context_t *ctx) {
    send_status_response(ctx->client_fd, HTTP_404_NOT_FOUND);
    LOG_DEBUG("Sent 404 Not Found for path: %s", ctx->path);
}
