package com.innowise.authservice.service;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.model.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private JwtProperties jwtProperties;

    @InjectMocks
    private JwtService jwtService;

    private static final String SECRET = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private static final long ACCESS_EXPIRATION = 900000L;
    private static final long REFRESH_EXPIRATION = 604800000L;

    @BeforeEach
    void setUp() {
        when(jwtProperties.getSecret()).thenReturn(SECRET);
    }

    @Test
    void generateAccessToken_shouldContainUserIdAndRole() {
        when(jwtProperties.getSecret()).thenReturn(SECRET);
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(ACCESS_EXPIRATION);

        String token = jwtService.generateAccessToken(1L, Role.USER);

        assertThat(token).isNotBlank();
        assertThat(jwtService.extractUserId(token)).isEqualTo(1L);
        assertThat(jwtService.extractRole(token)).isEqualTo(Role.USER);
    }

    @Test
    void generateAccessToken_adminRole_shouldContainAdminRole() {
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(ACCESS_EXPIRATION);
        String token = jwtService.generateAccessToken(2L, Role.ADMIN);

        assertThat(jwtService.extractRole(token)).isEqualTo(Role.ADMIN);
    }

    @Test
    void generateRefreshToken_shouldBeValid() {
        when(jwtProperties.getRefreshTokenExpiration()).thenReturn(REFRESH_EXPIRATION);
        String token = jwtService.generateRefreshToken(1L);

        assertThat(token).isNotBlank();
        assertThat(jwtService.validateToken(token)).isTrue();
        assertThat(jwtService.extractUserId(token)).isEqualTo(1L);
    }

    @Test
    void validateToken_withValidToken_shouldReturnTrue() {
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(ACCESS_EXPIRATION);
        String token = jwtService.generateAccessToken(1L, Role.USER);

        assertThat(jwtService.validateToken(token)).isTrue();
    }

    @Test
    void validateToken_withInvalidToken_shouldReturnFalse() {
        assertThat(jwtService.validateToken("invalid.token.here")).isFalse();
    }

    @Test
    void validateToken_withTamperedToken_shouldReturnFalse() {
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(ACCESS_EXPIRATION);
        String token = jwtService.generateAccessToken(1L, Role.USER);
        String tampered = token.substring(0, token.length() - 5) + "XXXXX";

        assertThat(jwtService.validateToken(tampered)).isFalse();
    }
}
