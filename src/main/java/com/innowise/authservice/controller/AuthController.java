package com.innowise.authservice.controller;

import com.innowise.authservice.dto.*;
import com.innowise.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for handling authentication-related operations.
 * Provides endpoints for token management including login, validation, refresh,
 * and credentials management for administrative users.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Authenticates a user and returns an access token.
     * This endpoint accepts login credentials and validates them against the
     * authentication service. Upon successful authentication, it returns a token
     * that can be used for subsequent authenticated requests.
     *
     * @param request the login request containing user credentials (login and password)
     * @return ResponseEntity containing TokenResponse with the access token and related information
     * @see TokenResponse
     * @see LoginRequest
     */
    @PostMapping("/token")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * Validates an existing token and returns its validation status.
     * This endpoint checks whether a provided token is valid, active, and not expired.
     * It returns information about the token's validity status and associated user details if the token is valid.
     *
     * @param request the token validation request containing the token to validate
     * @return ResponseEntity containing ValidateTokenResponse with validation status and user information
     * @see ValidateTokenResponse
     * @see ValidateTokenRequest
     */
    @PostMapping("/validate")
    public ResponseEntity<ValidateTokenResponse> validate(@Valid @RequestBody ValidateTokenRequest request) {
        return ResponseEntity.ok(authService.validate(request));
    }

    /**
     * Refreshes an expired or soon-expiring token and returns a new token.
     * This endpoint accepts a valid but potentially expired token and generates
     * a new access token. This allows users to maintain their session without
     * needing to re-authenticate with their credentials.
     *
     * @param request the token refresh request containing the current token
     * @return ResponseEntity containing TokenResponse with the refreshed access token
     * @see TokenResponse
     * @see RefreshTokenRequest
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    /**
     * Saves user credentials for a new or existing user (ADMIN only).
     * This administrative endpoint creates or updates user credentials in the system.
     * It requires the caller to have the ADMIN role. The endpoint returns HTTP 201 CREATED
     * upon successful credential storage.
     *
     * @param request the credentials save request containing user information
     * @return ResponseEntity with HTTP status CREATED (201) indicating successful credential save
     * @see SaveCredentialsRequest
     */
    @PostMapping("/credentials")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> saveCredentials(@Valid @RequestBody SaveCredentialsRequest request) {
        authService.saveCredentials(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /**
     * Deletes user credentials by user ID (ADMIN only).
     * This administrative endpoint removes user credentials from the system for a
     * specified user ID. It requires the caller to have the ADMIN role. The endpoint
     * returns HTTP 204 NO CONTENT upon successful deletion.
     *
     * @param userId the unique identifier of the user whose credentials should be deleted
     * @return ResponseEntity with HTTP status NO_CONTENT (204) indicating successful deletion
     */
    @DeleteMapping("/credentials/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteCredentials(@PathVariable Long userId) {
        authService.deleteCredentialsByUserId(userId);
        return ResponseEntity.noContent().build();
    }
}
