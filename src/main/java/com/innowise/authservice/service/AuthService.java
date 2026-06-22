package com.innowise.authservice.service;

import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RefreshTokenRequest;
import com.innowise.authservice.dto.SaveCredentialsRequest;
import com.innowise.authservice.dto.TokenResponse;
import com.innowise.authservice.dto.ValidateTokenRequest;
import com.innowise.authservice.dto.ValidateTokenResponse;

/**
 * Service interface for authentication and token management operations.
 * This interface defines the contract for handling user authentication,
 * JWT token issuance, validation, refresh, and credential management.
 * Implementations are responsible for coordinating with repositories,
 * JWT utilities, and password encoders to fulfill these operations.
 * @see com.innowise.authservice.service.impl.AuthServiceImpl
 * @see com.innowise.authservice.controller.AuthController
 */
public interface AuthService {

    /**
     * Saves user credentials in the system.
     * This method validates that the login doesn't already exist,
     * encodes the password using BCrypt with a unique salt,
     * and persists the user credentials to the database.
     * @param request the credentials save request containing login, password, userId, and role
     * @throws com.innowise.authservice.exception.AuthServiceException
     *         with HTTP status CONFLICT (409) if login already exists
     * @throws com.innowise.authservice.exception.AuthServiceException
     *         with HTTP status BAD_REQUEST (400) if validation fails
     * @see SaveCredentialsRequest
     */
    void saveCredentials(SaveCredentialsRequest request);

    /**
     * Authenticates a user and returns a token pair.
     * Validates the provided login and password against stored credentials.
     * Upon successful authentication, generates a new access token (short-lived)
     * and a refresh token (long-lived). The refresh token is persisted in the
     * database for subsequent refresh operations and revocation capabilities.
     * @param request the login request containing user login and password
     * @return TokenResponse containing access token and refresh token
     * @throws com.innowise.authservice.exception.AuthServiceException
     *         with HTTP status UNAUTHORIZED (401) if login or password is invalid
     * @throws com.innowise.authservice.exception.AuthServiceException
     *         with HTTP status FORBIDDEN (403) if user account is deactivated
     * @see LoginRequest
     * @see TokenResponse
     */
    TokenResponse login(LoginRequest request);

    /**
     * Refreshes an expired access token using a valid refresh token.
     * This method implements refresh token rotation pattern:
     *   Validates that the refresh token exists, is not revoked, and not expired
     *   Verifies the token's cryptographic signature
     *   Revokes all existing refresh tokens for the user
     *   Generates a fresh token pair (new access + new refresh)
     *   Persists the new refresh token in the database
     * Note:This operation invalidates the refresh token used,
     * implementing one-time-use semantics for enhanced security.
     *
     * @param request the refresh request containing the refresh token
     * @return TokenResponse containing new access token and new refresh token
     * @throws com.innowise.authservice.exception.AuthServiceException
     *         with HTTP status UNAUTHORIZED (401) if refresh token is not found, revoked, expired, or invalid
     * @throws com.innowise.authservice.exception.AuthServiceException
     *         with HTTP status NOT_FOUND (404) if user associated with token doesn't exist
     * @see RefreshTokenRequest
     * @see TokenResponse
     */
    TokenResponse refresh(RefreshTokenRequest request);

    /**
     * Validates a JWT token and returns its status with user information.
     *
     * Performs comprehensive token validation including:
     * - Signature verification (ensures token was issued by this service)
     * - Expiration check (rejects expired tokens)
     * - Structural integrity validation
     *
     * Important: This method does NOT throw exceptions on validation failure.
     * Instead, it returns a response with valid=false and null user information.
     * This design is suitable for public validation endpoints where invalid tokens are
     * expected and should not cause error responses.
     *
     * @param request the validation request containing the token to validate
     * @return ValidateTokenResponse containing:
     *         valid - true if token is valid, false otherwise
     *         userId - extracted user ID (null if invalid)
     *         role - extracted user role (null if invalid)
     * @see ValidateTokenRequest
     * @see ValidateTokenResponse
     */
    ValidateTokenResponse validate(ValidateTokenRequest request);

    /**
     * Deletes user credentials by user ID.
     *
     * This operation removes all authentication-related data for the specified user:
     * - User credentials (login, password hash) from the user_credential table
     * - All refresh tokens associated with the user from the refresh_token table
     *
     * Use Cases:
     * - User account deletion in the main user service
     * - Compliance with GDPR "right to be forgotten"
     * - Administrative cleanup of orphaned authentication data
     *
     * Access Control: This operation requires ADMIN role.
     *
     * Important: This is a hard delete. After this operation,
     * the user cannot authenticate and all their refresh tokens are immediately invalidated.
     * The operation is idempotent - calling with a non-existent userId does nothing.
     *
     * @param userId the unique identifier of the user whose credentials should be deleted
     * @throws com.innowise.authservice.exception.AuthServiceException
     *         with HTTP status NOT_FOUND (404) if user doesn't exist (optional, implementation-dependent)
     * @see com.innowise.authservice.repository.UserCredentialRepository
     * @see com.innowise.authservice.repository.RefreshTokenRepository
     */
    void deleteCredentialsByUserId(Long userId);
}
