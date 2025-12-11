/**
 * HTTP Server - Main Entry Point
 *
 * A lightweight HTTP/1.1 server with security hardening.
 *
 * Usage: ./http_server [--directory <path>]
 *
 * Features:
 * - Path-based routing (/, /echo, /user-agent, /files)
 * - Gzip compression support
 * - Path traversal protection
 * - Socket timeout protection
 * - Connection limiting
 */

#include "server/server.h"

// =============================================================================
// COMMAND LINE PARSING
// =============================================================================

static const char *parse_document_root(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--directory") == 0 && i + 1 < argc) {
            return argv[i + 1];
        }
    }
    return NULL;
}

static void print_usage(const char *program) {
    printf("Usage: %s [OPTIONS]\n\n", program);
    printf("Options:\n");
    printf("  --directory <path>  Set document root for /files endpoint\n");
    printf("\n");
}

// =============================================================================
// MAIN
// =============================================================================

int main(int argc, char *argv[]) {
    // Disable output buffering for immediate logging
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    // Parse command line arguments
    const char *document_root = parse_document_root(argc, argv);

    // Initialize server
    server_state_t server;
    if (server_init(&server, document_root) < 0) {
        LOG_ERROR("Failed to initialize server");
        return 1;
    }

    // Run server (blocks until stopped)
    int result = server_run(&server);

    // Cleanup
    server_cleanup(&server);

    return result;
}
