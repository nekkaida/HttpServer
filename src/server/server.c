/**
 * Server Module Implementation
 *
 * Main server lifecycle and connection handling.
 * Supports graceful shutdown via SIGTERM/SIGINT.
 */

#include "server.h"
#include "../http/http_parser.h"
#include "../handlers/handlers.h"
#include "../security/security.h"
#include "../compression/gzip.h"

// =============================================================================
// GLOBAL STATE FOR SIGNAL HANDLERS
// =============================================================================

static volatile sig_atomic_t g_shutdown_requested = 0;
static volatile int *g_active_connections = NULL;
static server_state_t *g_server_state = NULL;

// =============================================================================
// SIGNAL HANDLERS
// =============================================================================

static void handle_sigchld(int sig) {
    (void)sig;

    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        if (g_active_connections && *g_active_connections > 0) {
            (*g_active_connections)--;
        }
    }
    errno = saved_errno;
}

static void handle_shutdown_signal(int sig) {
    const char *sig_name = (sig == SIGTERM) ? "SIGTERM" : "SIGINT";

    // Use write() instead of printf() - it's async-signal-safe
    const char msg[] = "\n[INFO] Received shutdown signal, stopping server...\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);

    g_shutdown_requested = 1;

    if (g_server_state) {
        g_server_state->running = 0;
    }
}

// =============================================================================
// SERVER LIFECYCLE
// =============================================================================

int server_init(server_state_t *state, const char *document_root) {
    if (state == NULL) {
        return -1;
    }

    memset(state, 0, sizeof(*state));
    state->server_fd = -1;
    state->running = 0;

    // Store global reference for signal handlers
    g_server_state = state;

    // Initialize logging
    log_init(LOG_LEVEL_INFO, NULL, NULL);

    // Initialize gzip compression
    gzip_init();

    // Initialize document root if provided
    if (document_root != NULL) {
        state->raw_document_root = (char *)document_root;
        if (security_init_document_root(document_root, state->document_root) < 0) {
            LOG_ERROR("Failed to initialize document root: %s", document_root);
            return -1;
        }
        LOG_INFO("Document root: %s", document_root);
        LOG_INFO("Resolved path: %s", state->document_root);
    }

    // Set up signal handler for SIGCHLD (child process reaping)
    g_active_connections = &state->active_connections;
    struct sigaction sa_chld;
    sa_chld.sa_handler = handle_sigchld;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa_chld, NULL) == -1) {
        LOG_ERROR("Failed to set SIGCHLD handler: %s", strerror(errno));
        return -1;
    }

    // Set up signal handlers for graceful shutdown
    struct sigaction sa_term;
    sa_term.sa_handler = handle_shutdown_signal;
    sigemptyset(&sa_term.sa_mask);
    sa_term.sa_flags = 0;  // Don't restart accept() - we want it to be interrupted

    if (sigaction(SIGTERM, &sa_term, NULL) == -1) {
        LOG_ERROR("Failed to set SIGTERM handler: %s", strerror(errno));
        return -1;
    }

    if (sigaction(SIGINT, &sa_term, NULL) == -1) {
        LOG_ERROR("Failed to set SIGINT handler: %s", strerror(errno));
        return -1;
    }

    // Create socket
    state->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (state->server_fd == -1) {
        LOG_ERROR("Socket creation failed: %s", strerror(errno));
        return -1;
    }

    // Set SO_REUSEADDR
    int reuse = 1;
    if (setsockopt(state->server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        LOG_ERROR("SO_REUSEADDR failed: %s", strerror(errno));
        close(state->server_fd);
        return -1;
    }

    // Bind to port
    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERVER_PORT),
        .sin_addr = { htonl(INADDR_ANY) },
    };

    if (bind(state->server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        LOG_ERROR("Bind failed: %s", strerror(errno));
        close(state->server_fd);
        return -1;
    }

    // Start listening
    if (listen(state->server_fd, CONNECTION_BACKLOG) != 0) {
        LOG_ERROR("Listen failed: %s", strerror(errno));
        close(state->server_fd);
        return -1;
    }

    return 0;
}

int server_run(server_state_t *state) {
    if (state == NULL || state->server_fd < 0) {
        return -1;
    }

    state->running = 1;

    LOG_INFO("===========================================");
    LOG_INFO("HTTP Server v1.2 (Security Hardened)");
    LOG_INFO("===========================================");
    LOG_INFO("Server started on port %d", SERVER_PORT);
    LOG_INFO("Press Ctrl+C to stop");

    // Print security configuration
    LOG_INFO("--- Security Configuration ---");
    LOG_INFO("Max connections: %d", MAX_CONNECTIONS);
    LOG_INFO("Socket timeout: %d seconds", SOCKET_TIMEOUT_SEC);
    LOG_INFO("Max request size: %d bytes", REQUEST_BUFFER_SIZE);
    LOG_INFO("Max body size: %d bytes", MAX_BODY_SIZE);
    LOG_INFO("Path traversal protection: ENABLED");
    LOG_INFO("Method whitelist: GET, POST, HEAD");
    LOG_INFO("Graceful shutdown: ENABLED");
    LOG_INFO("------------------------------");

    struct sockaddr_in client_addr;
    socklen_t client_addr_len;

    while (state->running && !g_shutdown_requested) {
        // Check connection limit
        if (state->active_connections >= MAX_CONNECTIONS) {
            LOG_WARN("Max connections (%d) reached, rejecting new connections",
                     MAX_CONNECTIONS);
            usleep(10000);  // 10ms
            continue;
        }

        client_addr_len = sizeof(client_addr);
        int client_fd = accept(state->server_fd, (struct sockaddr *)&client_addr,
                               &client_addr_len);

        if (client_fd < 0) {
            if (errno == EINTR) {
                // Interrupted by signal - check if we should shutdown
                if (g_shutdown_requested) {
                    LOG_INFO("Accept interrupted by shutdown signal");
                    break;
                }
                continue;
            }
            LOG_ERROR("Accept failed: %s", strerror(errno));
            continue;
        }

        // Get client IP for logging
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        state->active_connections++;
        LOG_INFO("Client connected from %s (active: %d)", client_ip, state->active_connections);

        // Fork child process
        pid_t pid = fork();

        if (pid < 0) {
            LOG_ERROR("Fork failed: %s", strerror(errno));
            close(client_fd);
            state->active_connections--;
            continue;
        } else if (pid == 0) {
            // Child process
            close(state->server_fd);
            server_handle_client(client_fd, state, client_ip);
            close(client_fd);
            exit(0);
        } else {
            // Parent process
            close(client_fd);
            LOG_DEBUG("Created child process PID: %d", pid);
        }
    }

    // Graceful shutdown - wait for active connections
    if (state->active_connections > 0) {
        LOG_INFO("Waiting for %d active connection(s) to finish...",
                 state->active_connections);

        // Wait up to 5 seconds for connections to close
        int wait_time = 0;
        while (state->active_connections > 0 && wait_time < 5000) {
            usleep(100000);  // 100ms
            wait_time += 100;
        }

        if (state->active_connections > 0) {
            LOG_WARN("Forcing shutdown with %d active connections",
                     state->active_connections);
        }
    }

    LOG_INFO("Server stopped");
    return 0;
}

void server_stop(server_state_t *state) {
    if (state) {
        state->running = 0;
        g_shutdown_requested = 1;
    }
}

void server_cleanup(server_state_t *state) {
    if (state) {
        if (state->server_fd >= 0) {
            close(state->server_fd);
            state->server_fd = -1;
        }
        g_server_state = NULL;
    }

    // Shutdown logging
    log_shutdown();
}

// =============================================================================
// CONNECTION HANDLING
// =============================================================================

void server_handle_client(int client_fd, const server_state_t *state, const char *client_ip) {
    // Set socket timeouts
    set_socket_timeout(client_fd, SOCKET_TIMEOUT_SEC);

    // Read request
    char buffer[REQUEST_BUFFER_SIZE] = {0};
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            LOG_SECURITY("Connection timeout from %s - possible slowloris attack", client_ip);
        } else {
            LOG_DEBUG("Failed to read request from %s (errno: %d)", client_ip, errno);
        }
        return;
    }

    buffer[bytes_read] = '\0';
    LOG_DEBUG("Received request from %s (%zd bytes)", client_ip, bytes_read);

    // Validate HTTP method
    if (!validate_http_method(buffer)) {
        send(client_fd, HTTP_405_METHOD_NOT_ALLOWED,
             strlen(HTTP_405_METHOD_NOT_ALLOWED), 0);
        LOG_SECURITY("Invalid HTTP method rejected from %s", client_ip);
        return;
    }

    // HTTP/1.1 compliance: Validate Host header
    int http_version = http_get_version(buffer);
    if (http_version >= 11 && !http_validate_host_header(buffer)) {
        send(client_fd, HTTP_400_BAD_REQUEST, strlen(HTTP_400_BAD_REQUEST), 0);
        LOG_SECURITY("Missing Host header in HTTP/1.1 request from %s", client_ip);
        return;
    }

    // Extract path
    char *path = http_extract_path(buffer);

    // Validate path characters
    if (!is_safe_path_chars(path)) {
        send(client_fd, HTTP_400_BAD_REQUEST, strlen(HTTP_400_BAD_REQUEST), 0);
        LOG_SECURITY("Invalid characters in path from %s: %s", client_ip, path);
        return;
    }

    // Get User-Agent for access logging
    char *user_agent = http_extract_header(buffer, "User-Agent");

    // Build handler context
    handler_context_t ctx = {
        .client_fd = client_fd,
        .request = buffer,
        .path = path,
        .supports_gzip = http_client_supports_gzip(buffer),
        .document_root = state->document_root[0] ? state->document_root : NULL,
        .client_ip = client_ip,
    };

    // Route to appropriate handler
    int status_code = HTTP_STATUS_OK;
    size_t bytes_sent = 0;

    if (strcmp(path, "/") == 0) {
        handle_root(&ctx);
        status_code = HTTP_STATUS_OK;
    } else if (strcmp(path, "/health") == 0) {
        handle_health(&ctx);
        status_code = HTTP_STATUS_OK;
    } else if (http_path_starts_with(path, "/echo/")) {
        handle_echo(&ctx);
        status_code = HTTP_STATUS_OK;
    } else if (strcmp(path, "/user-agent") == 0) {
        handle_user_agent(&ctx);
        status_code = HTTP_STATUS_OK;
    } else if (http_path_starts_with(path, "/files/") && ctx.document_root != NULL) {
        handle_files(&ctx, http_is_post_request(buffer));
        status_code = HTTP_STATUS_OK;  // Could be 201, 404, etc.
    } else {
        handle_not_found(&ctx);
        status_code = HTTP_STATUS_NOT_FOUND;
    }

    // Log access
    log_access_simple(client_ip, buffer, status_code, bytes_sent, user_agent);
}
