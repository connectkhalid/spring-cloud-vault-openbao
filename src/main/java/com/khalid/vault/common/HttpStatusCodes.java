package com.khalid.vault.common;

import org.springframework.http.HttpStatus;

/** Canonical HTTP statuses and numeric codes used by API and integration error handling. */
public final class HttpStatusCodes {
    public static final HttpStatus BAD_REQUEST = HttpStatus.BAD_REQUEST;
    public static final HttpStatus NOT_ACCEPTABLE = HttpStatus.NOT_ACCEPTABLE;
    public static final HttpStatus UNAUTHORIZED = HttpStatus.UNAUTHORIZED;
    public static final HttpStatus FORBIDDEN = HttpStatus.FORBIDDEN;
    public static final HttpStatus NOT_FOUND = HttpStatus.NOT_FOUND;
    public static final HttpStatus GONE = HttpStatus.GONE;
    public static final HttpStatus NO_CONTENT = HttpStatus.NO_CONTENT;
    public static final HttpStatus CONFLICT = HttpStatus.CONFLICT;
    public static final HttpStatus BAD_GATEWAY = HttpStatus.BAD_GATEWAY;
    public static final HttpStatus METHOD_NOT_ALLOWED = HttpStatus.METHOD_NOT_ALLOWED;
    public static final HttpStatus UNSUPPORTED_MEDIA_TYPE = HttpStatus.UNSUPPORTED_MEDIA_TYPE;
    public static final HttpStatus INTERNAL_SERVER_ERROR = HttpStatus.INTERNAL_SERVER_ERROR;

    public static final int BAD_REQUEST_CODE = BAD_REQUEST.value();
    public static final int NOT_ACCEPTABLE_CODE = NOT_ACCEPTABLE.value();
    public static final int UNAUTHORIZED_CODE = UNAUTHORIZED.value();
    public static final int FORBIDDEN_CODE = FORBIDDEN.value();
    public static final int NOT_FOUND_CODE = NOT_FOUND.value();
    public static final int GONE_CODE = GONE.value();
    public static final int NO_CONTENT_CODE = NO_CONTENT.value();
    public static final int CONFLICT_CODE = CONFLICT.value();
    public static final int BAD_GATEWAY_CODE = BAD_GATEWAY.value();
    public static final int METHOD_NOT_ALLOWED_CODE = METHOD_NOT_ALLOWED.value();
    public static final int UNSUPPORTED_MEDIA_TYPE_CODE = UNSUPPORTED_MEDIA_TYPE.value();
    public static final int INTERNAL_SERVER_ERROR_CODE = INTERNAL_SERVER_ERROR.value();

    private HttpStatusCodes() { }
}
