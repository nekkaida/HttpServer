#ifndef HTTP_SERVER_LOGGING_H
#define HTTP_SERVER_LOGGING_H

/**
 * Logging Module
 *
 * Provides structured logging with:
 * - Multiple log levels (DEBUG, INFO, WARN, ERROR, SECURITY)
 * - Timestamps
 * - Process ID tracking
 * - Access logging (Apache combined format)
 * - File and stdout output
 */

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

// =============================================================================
// LOG LEVELS
// =============================================================================

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_SECURITY = 4,
    LOG_LEVEL_NONE = 5
} log_level_t;

// =============================================================================
// CONFIGURATION
// =============================================================================

/**
 * Initialize the logging system.
 *
 * @param level Minimum log level to output
 * @param log_file Path to log file (NULL for stdout only)
 * @param access_log Path to access log file (NULL to disable)
 * @return 0 on success, -1 on error
 */
int log_init(log_level_t level, const char *log_file, const char *access_log);

/**
 * Shutdown the logging system and flush buffers.
 */
void log_shutdown(void);

/**
 * Set the minimum log level.
 *
 * @param level New minimum log level
 */
void log_set_level(log_level_t level);

/**
 * Get the current log level.
 *
 * @return Current log level
 */
log_level_t log_get_level(void);

// =============================================================================
// LOGGING FUNCTIONS
// =============================================================================

/**
 * Log a message at the specified level.
 *
 * @param level Log level
 * @param file Source file name
 * @param line Source line number
 * @param fmt Printf-style format string
 * @param ... Format arguments
 */
void log_message(log_level_t level, const char *file, int line,
                 const char *fmt, ...);

// Convenience macros with file/line info
#define LOG_DEBUG(fmt, ...) \
    log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    log_message(LOG_LEVEL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    log_message(LOG_LEVEL_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
    log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_SECURITY(fmt, ...) \
    log_message(LOG_LEVEL_SECURITY, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

// =============================================================================
// ACCESS LOGGING
// =============================================================================

/**
 * Log an HTTP access in Apache combined log format.
 *
 * Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
 *
 * @param client_ip Client IP address string
 * @param method HTTP method (GET, POST, etc.)
 * @param path Request path
 * @param http_version HTTP version string
 * @param status_code Response status code
 * @param bytes_sent Response body size
 * @param referer Referer header (or "-")
 * @param user_agent User-Agent header (or "-")
 */
void log_access(const char *client_ip, const char *method, const char *path,
                const char *http_version, int status_code, size_t bytes_sent,
                const char *referer, const char *user_agent);

/**
 * Simplified access log for common case.
 *
 * @param client_ip Client IP address
 * @param request First line of HTTP request
 * @param status_code Response status code
 * @param bytes_sent Response body size
 * @param user_agent User-Agent header
 */
void log_access_simple(const char *client_ip, const char *request,
                       int status_code, size_t bytes_sent,
                       const char *user_agent);

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Get the current timestamp in ISO 8601 format.
 *
 * @param buffer Output buffer (at least 32 bytes)
 * @param size Buffer size
 */
void log_get_timestamp(char *buffer, size_t size);

/**
 * Get the current timestamp in Apache log format.
 *
 * @param buffer Output buffer (at least 32 bytes)
 * @param size Buffer size
 */
void log_get_timestamp_apache(char *buffer, size_t size);

/**
 * Get log level name as string.
 *
 * @param level Log level
 * @return Level name string
 */
const char* log_level_name(log_level_t level);

#endif // HTTP_SERVER_LOGGING_H
