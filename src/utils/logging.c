/**
 * Logging Module Implementation
 *
 * Thread-safe logging with multiple outputs and access logging.
 */

#include "logging.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

// =============================================================================
// INTERNAL STATE
// =============================================================================

static struct {
    log_level_t level;
    FILE *log_fp;
    FILE *access_fp;
    int initialized;
    pthread_mutex_t mutex;
} log_state = {
    .level = LOG_LEVEL_INFO,
    .log_fp = NULL,
    .access_fp = NULL,
    .initialized = 0
};

// Log level names
static const char *level_names[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "SECURITY",
    "NONE"
};

// Log level colors (ANSI)
static const char *level_colors[] = {
    "\033[36m",    // DEBUG: cyan
    "\033[32m",    // INFO: green
    "\033[33m",    // WARN: yellow
    "\033[31m",    // ERROR: red
    "\033[35m",    // SECURITY: magenta
    ""             // NONE
};

static const char *color_reset = "\033[0m";

// =============================================================================
// INITIALIZATION
// =============================================================================

int log_init(log_level_t level, const char *log_file, const char *access_log) {
    if (log_state.initialized) {
        log_shutdown();
    }

    pthread_mutex_init(&log_state.mutex, NULL);
    log_state.level = level;

    // Open log file if specified
    if (log_file != NULL) {
        log_state.log_fp = fopen(log_file, "a");
        if (log_state.log_fp == NULL) {
            fprintf(stderr, "Failed to open log file: %s (errno: %d)\n",
                    log_file, errno);
            return -1;
        }
        // Line buffered for real-time logging
        setvbuf(log_state.log_fp, NULL, _IOLBF, 0);
    }

    // Open access log if specified
    if (access_log != NULL) {
        log_state.access_fp = fopen(access_log, "a");
        if (log_state.access_fp == NULL) {
            fprintf(stderr, "Failed to open access log: %s (errno: %d)\n",
                    access_log, errno);
            if (log_state.log_fp) {
                fclose(log_state.log_fp);
                log_state.log_fp = NULL;
            }
            return -1;
        }
        setvbuf(log_state.access_fp, NULL, _IOLBF, 0);
    }

    log_state.initialized = 1;
    return 0;
}

void log_shutdown(void) {
    pthread_mutex_lock(&log_state.mutex);

    if (log_state.log_fp != NULL) {
        fflush(log_state.log_fp);
        fclose(log_state.log_fp);
        log_state.log_fp = NULL;
    }

    if (log_state.access_fp != NULL) {
        fflush(log_state.access_fp);
        fclose(log_state.access_fp);
        log_state.access_fp = NULL;
    }

    log_state.initialized = 0;
    pthread_mutex_unlock(&log_state.mutex);
    pthread_mutex_destroy(&log_state.mutex);
}

void log_set_level(log_level_t level) {
    log_state.level = level;
}

log_level_t log_get_level(void) {
    return log_state.level;
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

void log_get_timestamp(char *buffer, size_t size) {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm *tm_info = localtime(&tv.tv_sec);

    // ISO 8601 format: 2024-01-15T14:30:45.123
    snprintf(buffer, size, "%04d-%02d-%02dT%02d:%02d:%02d.%03ld",
             tm_info->tm_year + 1900,
             tm_info->tm_mon + 1,
             tm_info->tm_mday,
             tm_info->tm_hour,
             tm_info->tm_min,
             tm_info->tm_sec,
             tv.tv_usec / 1000);
}

void log_get_timestamp_apache(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    // Apache format: [15/Jan/2024:14:30:45 +0000]
    strftime(buffer, size, "[%d/%b/%Y:%H:%M:%S %z]", tm_info);
}

const char* log_level_name(log_level_t level) {
    if (level >= 0 && level <= LOG_LEVEL_NONE) {
        return level_names[level];
    }
    return "UNKNOWN";
}

// =============================================================================
// LOGGING FUNCTIONS
// =============================================================================

void log_message(log_level_t level, const char *file, int line,
                 const char *fmt, ...) {
    // Check if we should log this level
    if (level < log_state.level) {
        return;
    }

    // Get timestamp
    char timestamp[32];
    log_get_timestamp(timestamp, sizeof(timestamp));

    // Extract filename from path
    const char *filename = file;
    const char *last_sep = strrchr(file, '/');
    if (last_sep) {
        filename = last_sep + 1;
    }
#ifdef _WIN32
    last_sep = strrchr(filename, '\\');
    if (last_sep) {
        filename = last_sep + 1;
    }
#endif

    // Format the message
    char message[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    // Build the log line
    char log_line[2048];
    snprintf(log_line, sizeof(log_line),
             "%s [%s] [%s:%d] [PID:%d] %s\n",
             timestamp,
             level_names[level],
             filename,
             line,
             getpid(),
             message);

    // Output to stdout with colors
    pthread_mutex_lock(&log_state.mutex);

    // Check if stdout is a TTY for colors
    int use_colors = isatty(fileno(stdout));

    if (use_colors) {
        fprintf(stdout, "%s%s%s [%s%s%s] [%s:%d] [PID:%d] %s\n",
                level_colors[level], timestamp, color_reset,
                level_colors[level], level_names[level], color_reset,
                filename, line, getpid(), message);
    } else {
        fputs(log_line, stdout);
    }
    fflush(stdout);

    // Output to log file (no colors)
    if (log_state.log_fp != NULL) {
        fputs(log_line, log_state.log_fp);
    }

    pthread_mutex_unlock(&log_state.mutex);
}

// =============================================================================
// ACCESS LOGGING
// =============================================================================

void log_access(const char *client_ip, const char *method, const char *path,
                const char *http_version, int status_code, size_t bytes_sent,
                const char *referer, const char *user_agent) {
    char timestamp[32];
    log_get_timestamp_apache(timestamp, sizeof(timestamp));

    // Apache combined log format:
    // %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
    char log_line[2048];
    snprintf(log_line, sizeof(log_line),
             "%s - - %s \"%s %s %s\" %d %zu \"%s\" \"%s\"\n",
             client_ip ? client_ip : "-",
             timestamp,
             method ? method : "-",
             path ? path : "-",
             http_version ? http_version : "HTTP/1.1",
             status_code,
             bytes_sent,
             referer ? referer : "-",
             user_agent ? user_agent : "-");

    pthread_mutex_lock(&log_state.mutex);

    // Always output to stdout for now
    fputs(log_line, stdout);
    fflush(stdout);

    // Output to access log file
    if (log_state.access_fp != NULL) {
        fputs(log_line, log_state.access_fp);
    }

    pthread_mutex_unlock(&log_state.mutex);
}

void log_access_simple(const char *client_ip, const char *request,
                       int status_code, size_t bytes_sent,
                       const char *user_agent) {
    // Parse method and path from request line
    char method[16] = "-";
    char path[1024] = "-";
    char version[16] = "HTTP/1.1";

    if (request != NULL) {
        sscanf(request, "%15s %1023s %15s", method, path, version);
    }

    log_access(client_ip, method, path, version, status_code, bytes_sent,
               NULL, user_agent);
}
