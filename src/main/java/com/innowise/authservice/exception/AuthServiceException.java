package com.innowise.authservice.exception;

import org.springframework.http.HttpStatus;

public class AuthServiceException extends RuntimeException {

    private final HttpStatus status;

    public AuthServiceException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
