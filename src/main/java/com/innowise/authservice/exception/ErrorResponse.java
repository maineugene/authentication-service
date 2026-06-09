package com.innowise.authservice.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

    private int status;
    private String error;
    private String message;
    private LocalDateTime timestamp;
    private Map<String, String> details;

    public static ErrorResponse of(int status, String error, String message) {
        return new ErrorResponse(status, error, message, LocalDateTime.now(), null);
    }

    public static ErrorResponse withDetails(int status, String error, String message, Map<String, String> details) {
        return new ErrorResponse(status, error, message, LocalDateTime.now(), details);
    }
}