package com.khalid.vault.common;

import com.khalid.vault.audit.AuditLoggerService;
import com.khalid.vault.dto.common.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final AuditLoggerService auditLogger;

    public GlobalExceptionHandler(AuditLoggerService auditLogger) {
        this.auditLogger = auditLogger;
    }

    @ExceptionHandler(ApiException.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleApiException(
            ApiException exception, HttpServletRequest request) {
        return error(exception.status(), exception.code(), exception.getMessage(), Map.of(), request, exception);
    }

    @ExceptionHandler(ResponseStatusException.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleStatusException(
            ResponseStatusException exception, HttpServletRequest request) {
        HttpStatus status = HttpStatus.valueOf(exception.getStatusCode().value());
        String message = exception.getReason() == null ? "Request could not be completed" : exception.getReason();
        return error(status, codeFor(status), message, Map.of(), request, exception);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleValidation(
            MethodArgumentNotValidException exception, HttpServletRequest request) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError fieldError : exception.getBindingResult().getFieldErrors()) {
            fields.putIfAbsent(fieldError.getField(), fieldError.getDefaultMessage());
        }
        return error(HttpStatusCodes.BAD_REQUEST, "VALIDATION_FAILED", "Request validation failed",
                fields, request, exception);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleConstraintViolation(
            ConstraintViolationException exception, HttpServletRequest request) {
        Map<String, String> fields = new LinkedHashMap<>();
        exception.getConstraintViolations().forEach(violation ->
                fields.putIfAbsent(violation.getPropertyPath().toString(), violation.getMessage()));
        return error(HttpStatusCodes.BAD_REQUEST, "VALIDATION_FAILED", "Request validation failed",
                fields, request, exception);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleUnreadable(
            HttpMessageNotReadableException exception, HttpServletRequest request) {
        return error(HttpStatusCodes.BAD_REQUEST, "INVALID_REQUEST_BODY", "Request body is missing or malformed",
                Map.of(), request, exception);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleMissingParameter(
            MissingServletRequestParameterException exception, HttpServletRequest request) {
        return error(HttpStatusCodes.BAD_REQUEST, "MISSING_PARAMETER",
                "Required parameter is missing: " + exception.getParameterName(), Map.of(), request, exception);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleMethodNotAllowed(
            HttpRequestMethodNotSupportedException exception, HttpServletRequest request) {
        return error(HttpStatusCodes.METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED",
                "HTTP method is not supported for this endpoint", Map.of(), request, exception);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleUnsupportedMediaType(
            HttpMediaTypeNotSupportedException exception, HttpServletRequest request) {
        return error(HttpStatusCodes.UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE",
                "Content type is not supported for this endpoint", Map.of(), request, exception);
    }

    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleNotAcceptable(
            HttpMediaTypeNotAcceptableException exception, HttpServletRequest request) {
        return error(HttpStatusCodes.NOT_ACCEPTABLE, "NOT_ACCEPTABLE",
                "Requested response type is not available", Map.of(), request, exception);
    }

    @ExceptionHandler(Exception.class)
    public org.springframework.http.ResponseEntity<ApiErrorResponse> handleUnexpected(
            Exception exception, HttpServletRequest request) {
        logger.error("Unhandled API exception path={} type={}", request.getRequestURI(), exception.getClass().getName());
        return error(HttpStatusCodes.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR",
                "An unexpected error occurred. Contact support with the request timestamp.",
                Map.of(), request, exception);
    }

    private org.springframework.http.ResponseEntity<ApiErrorResponse> error(HttpStatus status, String code,
            String message, Map<String, String> fields, HttpServletRequest request, Exception exception) {
        Instant timestamp = Instant.now();
        String actor = String.valueOf(request.getAttribute("actorId"));
        if ("null".equals(actor)) actor = "anonymous";
        auditLogger.apiFailure(actor, request.getMethod(), request.getRequestURI(), status.value(), code, message, exception);
        ApiErrorResponse body = new ApiErrorResponse(timestamp, status.value(), code, message,
                request.getRequestURI(), fields);
        return org.springframework.http.ResponseEntity.status(status).body(body);
    }

    private static String codeFor(HttpStatus status) {
        return switch (status) {
            case BAD_REQUEST -> "BAD_REQUEST";
            case UNAUTHORIZED -> "UNAUTHORIZED";
            case FORBIDDEN -> "FORBIDDEN";
            case NOT_FOUND -> "NOT_FOUND";
            case GONE -> "KEY_EXPIRED";
            case CONFLICT -> "CONFLICT";
            case BAD_GATEWAY -> "UPSTREAM_FAILURE";
            default -> "REQUEST_FAILED";
        };
    }
}
