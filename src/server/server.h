#ifndef HTTP_SERVER_SERVER_H
#define HTTP_SERVER_SERVER_H

/**
 * Server Module
 *
 * Main server lifecycle management:
 * - Server initialization
 * - Connection handling
 * - Process management
 */

#include "../include/common.h"

// =============================================================================
// SERVER STATE
// =============================================================================

/**
 * Server configuration and state.
 */
typedef struct {
    int server_fd;                      // Server socket
    char document_root[PATH_MAX];       // Canonical document root path
    char *raw_document_root;            // Original document root (from args)
    volatile int active_connections;    // Current connection count
    volatile int running;               // Server running flag
} server_state_t;

// =============================================================================
// SERVER LIFECYCLE
// =============================================================================

/**
 * Initialize the server.
 *
 * @param state Server state to initialize
 * @param document_root Optional document root for file serving (can be NULL)
 * @return 0 on success, -1 on error
 */
int server_init(server_state_t *state, const char *document_root);

/**
 * Start the server main loop.
 * This function blocks and runs until the server is stopped.
 *
 * @param state Server state
 * @return 0 on clean shutdown, -1 on error
 */
int server_run(server_state_t *state);

/**
 * Stop the server gracefully.
 *
 * @param state Server state
 */
void server_stop(server_state_t *state);

/**
 * Clean up server resources.
 *
 * @param state Server state
 */
void server_cleanup(server_state_t *state);

// =============================================================================
// CONNECTION HANDLING
// =============================================================================

/**
 * Handle a client connection.
 * Called in child process after fork.
 *
 * @param client_fd Client socket
 * @param state Server state (for document root access)
 * @param client_ip Client IP address string
 */
void server_handle_client(int client_fd, const server_state_t *state, const char *client_ip);

#endif // HTTP_SERVER_SERVER_H
