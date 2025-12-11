#ifndef HTTP_SERVER_COMMON_H
#define HTTP_SERVER_COMMON_H

/**
 * Common includes and type definitions
 */

// Standard C headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>

// POSIX headers
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <fcntl.h>

// Project headers
#include "config.h"
#include "../utils/logging.h"

// =============================================================================
// HTTP METHOD TYPES
// =============================================================================

typedef enum {
    HTTP_METHOD_UNKNOWN = 0,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_HEAD
} http_method_t;

// =============================================================================
// HTTP STATUS CODES
// =============================================================================

#define HTTP_STATUS_OK 200
#define HTTP_STATUS_CREATED 201
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_FORBIDDEN 403
#define HTTP_STATUS_NOT_FOUND 404
#define HTTP_STATUS_METHOD_NOT_ALLOWED 405
#define HTTP_STATUS_PAYLOAD_TOO_LARGE 413
#define HTTP_STATUS_INTERNAL_ERROR 500
#define HTTP_STATUS_SERVICE_UNAVAILABLE 503

// HTTP response templates
#define HTTP_200_OK "HTTP/1.1 200 OK\r\n"
#define HTTP_201_CREATED "HTTP/1.1 201 Created\r\n\r\n"
#define HTTP_400_BAD_REQUEST "HTTP/1.1 400 Bad Request\r\n\r\n"
#define HTTP_403_FORBIDDEN "HTTP/1.1 403 Forbidden\r\n\r\n"
#define HTTP_404_NOT_FOUND "HTTP/1.1 404 Not Found\r\n\r\n"
#define HTTP_405_METHOD_NOT_ALLOWED "HTTP/1.1 405 Method Not Allowed\r\n\r\n"
#define HTTP_413_PAYLOAD_TOO_LARGE "HTTP/1.1 413 Payload Too Large\r\n\r\n"
#define HTTP_500_INTERNAL_ERROR "HTTP/1.1 500 Internal Server Error\r\n\r\n"
#define HTTP_503_SERVICE_UNAVAILABLE "HTTP/1.1 503 Service Unavailable\r\n\r\n"

#endif // HTTP_SERVER_COMMON_H
