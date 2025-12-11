/**
 * HTTP Parser Module Implementation
 *
 * Provides HTTP request parsing functions with proper bounds checking.
 */

#include "http_parser.h"

// =============================================================================
// REQUEST PARSING
// =============================================================================

char* http_extract_path(const char *request) {
    static char path[MAX_PATH_LEN];
    memset(path, 0, sizeof(path));

    if (request == NULL) {
        return path;
    }

    const char *path_start = NULL;
    int prefix_len = 0;

    // Check if this is a GET or POST request
    if (strncmp(request, "GET ", 4) == 0) {
        path_start = request + 4;
        prefix_len = 4;
    } else if (strncmp(request, "POST ", 5) == 0) {
        path_start = request + 5;
        prefix_len = 5;
    } else if (strncmp(request, "HEAD ", 5) == 0) {
        path_start = request + 5;
        prefix_len = 5;
    }

    if (path_start == NULL) {
        return path;
    }

    // Find the end of the path (marked by space before HTTP version)
    const char *path_end = strchr(path_start, ' ');
    if (path_end) {
        size_t path_length = path_end - path_start;
        if (path_length >= sizeof(path)) {
            path_length = sizeof(path) - 1;
        }
        strncpy(path, path_start, path_length);
        path[path_length] = '\0';
    }

    return path;
}

char* http_extract_header(const char *request, const char *header_name) {
    static char value[MAX_PATH_LEN];
    memset(value, 0, sizeof(value));

    if (request == NULL || header_name == NULL) {
        return value;
    }

    // Create the header string to search for (case-insensitive)
    char search_header[256];
    int written = snprintf(search_header, sizeof(search_header), "\r\n%s: ", header_name);
    if (written < 0 || (size_t)written >= sizeof(search_header)) {
        return value;  // Header name too long
    }

    // Convert search header to lowercase for case-insensitive search
    for (int i = 0; search_header[i]; i++) {
        search_header[i] = tolower(search_header[i]);
    }

    // Create lowercase version of request for searching
    char *lower_request = strdup(request);
    if (lower_request == NULL) {
        return value;  // Memory allocation failed
    }

    for (int i = 0; lower_request[i]; i++) {
        lower_request[i] = tolower(lower_request[i]);
    }

    // Look for the header
    char *header_pos = strstr(lower_request, search_header);
    if (header_pos) {
        // Calculate the position in the original request
        size_t offset = header_pos - lower_request;

        // Get position after the header name and colon
        const char *value_start = request + offset + strlen(search_header);

        // Find the end of the value (marked by CRLF)
        const char *value_end = strstr(value_start, "\r\n");
        if (value_end) {
            // Calculate the value length with bounds checking
            size_t value_length = value_end - value_start;
            if (value_length >= sizeof(value)) {
                value_length = sizeof(value) - 1;
            }

            // Extract the value
            strncpy(value, value_start, value_length);
            value[value_length] = '\0';
        }
    }

    // Free the temporary lowercase request
    free(lower_request);

    return value;
}

char* http_extract_body(char *request, int *body_length) {
    if (request == NULL || body_length == NULL) {
        if (body_length) *body_length = 0;
        return NULL;
    }

    // Get Content-Length header
    char *content_length_str = http_extract_header(request, "Content-Length");
    if (content_length_str[0] != '\0') {
        *body_length = atoi(content_length_str);

        // Find the body (after \r\n\r\n)
        char *body_start = strstr(request, "\r\n\r\n");
        if (body_start) {
            body_start += 4;  // Skip the \r\n\r\n
            return body_start;
        }
    }

    *body_length = 0;
    return NULL;
}

// =============================================================================
// REQUEST TYPE DETECTION
// =============================================================================

int http_is_post_request(const char *request) {
    return request != NULL && strncmp(request, "POST ", 5) == 0;
}

int http_is_get_request(const char *request) {
    return request != NULL && strncmp(request, "GET ", 4) == 0;
}

http_method_t http_get_method(const char *request) {
    if (request == NULL) return HTTP_METHOD_UNKNOWN;

    if (strncmp(request, "GET ", 4) == 0) return HTTP_METHOD_GET;
    if (strncmp(request, "POST ", 5) == 0) return HTTP_METHOD_POST;
    if (strncmp(request, "HEAD ", 5) == 0) return HTTP_METHOD_HEAD;

    return HTTP_METHOD_UNKNOWN;
}

// =============================================================================
// PATH HELPERS
// =============================================================================

int http_path_starts_with(const char *path, const char *prefix) {
    if (path == NULL || prefix == NULL) return 0;
    return strncmp(path, prefix, strlen(prefix)) == 0;
}

char* http_extract_echo_string(const char *path) {
    static char echo_str[MAX_PATH_LEN];
    memset(echo_str, 0, sizeof(echo_str));

    if (path == NULL || strlen(path) <= 6) {
        return echo_str;
    }

    // Skip "/echo/" prefix
    const char *start = path + 6;

    // Copy with bounds checking
    size_t len = strlen(start);
    if (len >= sizeof(echo_str)) {
        len = sizeof(echo_str) - 1;
    }
    strncpy(echo_str, start, len);
    echo_str[len] = '\0';

    return echo_str;
}

char* http_extract_filename(const char *path) {
    static char filename[MAX_PATH_LEN];
    memset(filename, 0, sizeof(filename));

    if (path == NULL || strlen(path) <= 7) {
        return filename;
    }

    // Skip "/files/" prefix
    const char *start = path + 7;

    // Copy with bounds checking
    size_t len = strlen(start);
    if (len >= sizeof(filename)) {
        len = sizeof(filename) - 1;
    }
    strncpy(filename, start, len);
    filename[len] = '\0';

    return filename;
}

// =============================================================================
// COMPRESSION DETECTION
// =============================================================================

int http_client_supports_gzip(const char *request) {
    char *accept_encoding = http_extract_header(request, "Accept-Encoding");
    return strstr(accept_encoding, "gzip") != NULL;
}

// =============================================================================
// HTTP/1.1 COMPLIANCE
// =============================================================================

char* http_format_date(char *buffer, size_t buffer_size) {
    if (buffer == NULL || buffer_size < 32) {
        return NULL;
    }

    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);

    if (gmt == NULL) {
        return NULL;
    }

    // HTTP-date format: "Day, DD Mon YYYY HH:MM:SS GMT"
    strftime(buffer, buffer_size, "%a, %d %b %Y %H:%M:%S GMT", gmt);

    return buffer;
}

int http_validate_host_header(const char *request) {
    if (request == NULL) {
        return 0;
    }

    char *host = http_extract_header(request, "Host");

    // Host header must be present and non-empty for HTTP/1.1
    return host != NULL && host[0] != '\0';
}

int http_get_version(const char *request) {
    if (request == NULL) {
        return 0;
    }

    // Find HTTP version in the request line
    const char *http_pos = strstr(request, "HTTP/");
    if (http_pos == NULL) {
        return 0;
    }

    // Parse version number
    int major = 0, minor = 0;
    if (sscanf(http_pos, "HTTP/%d.%d", &major, &minor) != 2) {
        return 0;
    }

    // Return version as integer (10 for 1.0, 11 for 1.1, etc.)
    return major * 10 + minor;
}
