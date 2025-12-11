/**
 * Security Module Implementation
 *
 * Provides security functions for path validation, input sanitization,
 * and socket configuration to prevent common attacks.
 */

#include "security.h"

// =============================================================================
// PATH VALIDATION
// =============================================================================

int validate_file_path(const char *filename, char *resolved_path,
                       size_t resolved_size, const char *document_root) {
    // Check for null pointer
    if (filename == NULL || resolved_path == NULL || document_root == NULL ||
        document_root[0] == '\0') {
        return 0;
    }

    // Security check 1: Reject null bytes in filename (null byte injection)
    size_t filename_len = strlen(filename);
    if (memchr(filename, '\0', filename_len) != filename + filename_len) {
        LOG_SECURITY("Null byte injection attempt detected");
        return 0;
    }

    // Security check 2: Reject obviously malicious patterns early
    // This is defense-in-depth; realpath() is the authoritative check
    if (strstr(filename, "..") != NULL) {
        LOG_SECURITY("Path traversal pattern '..' detected in: %s", filename);
        return 0;
    }

    // Security check 3: Reject absolute paths
    if (filename[0] == '/') {
        LOG_SECURITY("Absolute path rejected: %s", filename);
        return 0;
    }

    // Build the full path
    char full_path[PATH_MAX];
    int written = snprintf(full_path, sizeof(full_path), "%s/%s",
                           document_root, filename);

    // Check for truncation
    if (written < 0 || (size_t)written >= sizeof(full_path)) {
        LOG_SECURITY("Path too long: %s", filename);
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
                LOG_SECURITY("Directory does not exist: %s", dir_path);
                return 0;
            }

            // Verify directory is within document root
            size_t root_len = strlen(document_root);
            if (strncmp(resolved_dir, document_root, root_len) != 0) {
                LOG_SECURITY("Directory traversal detected: %s resolves outside root",
                           filename);
                return 0;
            }

            // Reconstruct the full path with validated directory
            snprintf(resolved_path, resolved_size, "%s/%s",
                     resolved_dir, last_slash + 1 - dir_path + full_path);

            // One more check on the final filename component
            const char *final_name = last_slash + 1 - dir_path + full_path;
            if (strchr(final_name, '/') != NULL || strcmp(final_name, "..") == 0) {
                LOG_SECURITY("Invalid filename component: %s", final_name);
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
        LOG_SECURITY("realpath() failed for: %s (errno: %d)", full_path, errno);
        return 0;
    }

    // Security check 5: Verify the resolved path is within the document root
    size_t root_len = strlen(document_root);
    if (strncmp(resolved_path, document_root, root_len) != 0) {
        LOG_SECURITY("Path traversal detected: %s resolves to %s (outside root %s)",
                   filename, resolved_path, document_root);
        return 0;
    }

    // Security check 6: Ensure there's a path separator after the root
    // This prevents accessing /var/www/html-secret when root is /var/www/html
    if (resolved_path[root_len] != '\0' && resolved_path[root_len] != '/') {
        LOG_SECURITY("Path escapes root via prefix match: %s", resolved_path);
        return 0;
    }

    return 1;
}

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

// =============================================================================
// HTTP VALIDATION
// =============================================================================

int validate_http_method(const char *request) {
    if (request == NULL) return 0;

    // Whitelist of allowed methods
    if (strncmp(request, "GET ", 4) == 0) return 1;
    if (strncmp(request, "POST ", 5) == 0) return 1;
    if (strncmp(request, "HEAD ", 5) == 0) return 1;

    return 0;
}

// =============================================================================
// SOCKET SECURITY
// =============================================================================

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
// INITIALIZATION
// =============================================================================

int security_init_document_root(const char *path, char *resolved_root) {
    if (path == NULL || resolved_root == NULL) {
        return -1;
    }

    if (realpath(path, resolved_root) == NULL) {
        LOG_ERROR("Cannot resolve directory path: %s (errno: %d)", path, errno);
        return -1;
    }

    return 0;
}
