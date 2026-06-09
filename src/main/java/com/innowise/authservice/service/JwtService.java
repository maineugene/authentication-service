package com.innowise.authservice.service;

import com.innowise.authservice.model.Role;

import java.util.Date;

/**
 * Service interface for JSON Web Token (JWT) operations.
 * Provides methods for token generation, validation, and extracting claims.
 * This interface defines the contract for all JWT-related operations in the authentication service.
 */
public interface JwtService {
    /**
     * Generates a new access token for a user.
     * Access tokens are short-lived and contain user identification and role information.
     *
     * @param userId the unique identifier of the user
     * @param role the role assigned to the user (ADMIN or USER)
     * @return a compact, URL-safe JWT string
     */
    String generateAccessToken(Long userId, Role role);

    /**
     * Generates a new refresh token for a user.
     * Refresh tokens are long-lived and used to obtain new access tokens when they expire.
     *
     * @param userId the unique identifier of the user
     * @return a compact, URL-safe JWT string with type claim set to "refresh"
     */
    String generateRefreshToken(Long userId);

    /**
     * Validates a JWT token.
     * Checks signature, expiration, and structural integrity of the token.
     *
     * @param token the JWT string to validate
     * @return true if token is valid and not expired, false otherwise
     */
    boolean validateToken(String token);

    /**
     * Extracts user ID from a valid JWT token.
     *
     * @param token the valid JWT string
     * @return the user ID stored in the token's subject claim
     */
    Long extractUserId(String token);

    /**
     * Extracts user role from a valid JWT token.
     *
     * @param token the valid JWT string
     * @return the Role enum value stored in the token's "role" claim
     */
    Role extractRole(String token);

    /**
     * Extracts expiration date from a valid JWT token.
     *
     * @param token the valid JWT string
     * @return the expiration date from the token's "exp" claim
     */
    Date extractExpiration(String token);
}
