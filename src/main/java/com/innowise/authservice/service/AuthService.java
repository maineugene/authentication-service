package com.innowise.authservice.service;

import com.innowise.authservice.dto.*;
import com.innowise.authservice.exception.AuthServiceException;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.Role;
import com.innowise.authservice.model.UserCredential;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.repository.UserCredentialRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserCredentialRepository userCredentialRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Value("${jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    @Transactional
    public void saveCredentials(SaveCredentialsRequest request) {
        if (userCredentialRepository.existsByLogin(request.getLogin())) {
            throw new AuthServiceException("Login already exists", HttpStatus.CONFLICT);
        }

        UserCredential credential = UserCredential.builder()
                .userId(request.getUserId())
                .login(request.getLogin())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        userCredentialRepository.save(credential);
    }

    @Transactional
    public TokenResponse login(LoginRequest request) {
        UserCredential credential = userCredentialRepository.findByLogin(request.getLogin())
                .orElseThrow(() -> new AuthServiceException("Invalid login or password", HttpStatus.UNAUTHORIZED));

        if (!credential.isActive()) {
            throw new AuthServiceException("User account is deactivated", HttpStatus.FORBIDDEN);
        }

        if (!passwordEncoder.matches(request.getPassword(), credential.getPasswordHash())) {
            throw new AuthServiceException("Invalid login or password", HttpStatus.UNAUTHORIZED);
        }

        return issueTokenPair(credential.getUserId(), credential.getRole());
    }

    @Transactional
    public TokenResponse refresh(RefreshTokenRequest request) {
        RefreshToken stored = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new AuthServiceException("Refresh token not found", HttpStatus.UNAUTHORIZED));

        if (stored.isRevoked()) {
            throw new AuthServiceException("Refresh token has been revoked", HttpStatus.UNAUTHORIZED);
        }

        if (stored.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AuthServiceException("Refresh token has expired", HttpStatus.UNAUTHORIZED);
        }

        if (!jwtService.validateToken(request.getRefreshToken())) {
            throw new AuthServiceException("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }

        UserCredential credential = userCredentialRepository.findByUserId(stored.getUserId())
                .orElseThrow(() -> new AuthServiceException("User not found", HttpStatus.NOT_FOUND));

        refreshTokenRepository.revokeAllByUserId(stored.getUserId());

        return issueTokenPair(credential.getUserId(), credential.getRole());
    }

    public ValidateTokenResponse validate(ValidateTokenRequest request) {
        if (!jwtService.validateToken(request.getToken())) {
            return new ValidateTokenResponse(false, null, null);
        }
        Long userId = jwtService.extractUserId(request.getToken());
        Role role = jwtService.extractRole(request.getToken());
        return new ValidateTokenResponse(true, userId, role);
    }

    @Transactional
    public void deleteCredentialsByUserId(Long userId) {
        refreshTokenRepository.deleteAllByUserId(userId);
        userCredentialRepository.findByUserId(userId)
                .ifPresent(userCredentialRepository::delete);
    }

    private TokenResponse issueTokenPair(Long userId, Role role) {
        String accessToken = jwtService.generateAccessToken(userId, role);
        String rawRefreshToken = jwtService.generateRefreshToken(userId);

        refreshTokenRepository.revokeAllByUserId(userId);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .userId(userId)
                .token(rawRefreshToken)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000))
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        return new TokenResponse(accessToken, rawRefreshToken);
    }
}
