package com.innowise.authservice.service;

import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RefreshTokenRequest;
import com.innowise.authservice.dto.SaveCredentialsRequest;
import com.innowise.authservice.dto.TokenResponse;
import com.innowise.authservice.dto.ValidateTokenRequest;
import com.innowise.authservice.dto.ValidateTokenResponse;
import com.innowise.authservice.exception.AuthServiceException;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.Role;
import com.innowise.authservice.model.UserCredential;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.repository.UserCredentialRepository;
import com.innowise.authservice.service.impl.AuthServiceImpl;
import com.innowise.authservice.service.impl.JwtServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserCredentialRepository userCredentialRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtServiceImpl jwtService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "refreshTokenExpiration", 604800000L);
    }

    @Test
    void saveCredentials_withNewLogin_shouldSaveSuccessfully() {
        SaveCredentialsRequest request = new SaveCredentialsRequest();
        request.setUserId(1L);
        request.setLogin("john");
        request.setPassword("password");
        request.setRole(Role.USER);

        when(userCredentialRepository.existsByLogin("john")).thenReturn(false);
        when(passwordEncoder.encode("password")).thenReturn("hashed");

        authService.saveCredentials(request);

        verify(userCredentialRepository).save(any(UserCredential.class));
    }

    @Test
    void saveCredentials_withDuplicateLogin_shouldThrowConflict() {
        SaveCredentialsRequest request = new SaveCredentialsRequest();
        request.setLogin("john");
        request.setPassword("password");
        request.setRole(Role.USER);
        request.setUserId(1L);

        when(userCredentialRepository.existsByLogin("john")).thenReturn(true);

        assertThatThrownBy(() -> authService.saveCredentials(request))
                .isInstanceOf(AuthServiceException.class)
                .hasMessageContaining("Login already exists");
    }

    @Test
    void login_withValidCredentials_shouldReturnTokens() {
        LoginRequest request = new LoginRequest();
        request.setLogin("john");
        request.setPassword("password");

        UserCredential credential = UserCredential.builder()
                .userId(1L)
                .login("john")
                .passwordHash("hashed")
                .role(Role.USER)
                .active(true)
                .build();

        when(userCredentialRepository.findByLogin("john")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("password", "hashed")).thenReturn(true);
        when(jwtService.generateAccessToken(1L, Role.USER)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(1L)).thenReturn("refresh-token");

        TokenResponse response = authService.login(request);

        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
    }

    @Test
    void login_withWrongPassword_shouldThrowUnauthorized() {
        LoginRequest request = new LoginRequest();
        request.setLogin("john");
        request.setPassword("wrong");

        UserCredential credential = UserCredential.builder()
                .userId(1L)
                .login("john")
                .passwordHash("hashed")
                .role(Role.USER)
                .active(true)
                .build();

        when(userCredentialRepository.findByLogin("john")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("wrong", "hashed")).thenReturn(false);

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(AuthServiceException.class)
                .hasMessageContaining("Invalid login or password");
    }

    @Test
    void login_withDeactivatedUser_shouldThrowForbidden() {
        LoginRequest request = new LoginRequest();
        request.setLogin("john");
        request.setPassword("password");

        UserCredential credential = UserCredential.builder()
                .userId(1L)
                .login("john")
                .passwordHash("hashed")
                .role(Role.USER)
                .active(false)
                .build();

        when(userCredentialRepository.findByLogin("john")).thenReturn(Optional.of(credential));

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(AuthServiceException.class)
                .hasMessageContaining("deactivated");
    }

    @Test
    void login_withNonExistentUser_shouldThrowUnauthorized() {
        LoginRequest request = new LoginRequest();
        request.setLogin("unknown");
        request.setPassword("password");

        when(userCredentialRepository.findByLogin("unknown")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(AuthServiceException.class)
                .hasMessageContaining("Invalid login or password");
    }

    @Test
    void refresh_withValidToken_shouldReturnNewTokens() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("valid-refresh");

        RefreshToken stored = RefreshToken.builder()
                .userId(1L)
                .token("valid-refresh")
                .revoked(false)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();

        UserCredential credential = UserCredential.builder()
                .userId(1L)
                .role(Role.USER)
                .active(true)
                .build();

        when(refreshTokenRepository.findByToken("valid-refresh")).thenReturn(Optional.of(stored));
        when(jwtService.validateToken("valid-refresh")).thenReturn(true);
        when(userCredentialRepository.findByUserId(1L)).thenReturn(Optional.of(credential));
        when(jwtService.generateAccessToken(1L, Role.USER)).thenReturn("new-access");
        when(jwtService.generateRefreshToken(1L)).thenReturn("new-refresh");

        TokenResponse response = authService.refresh(request);

        assertThat(response.getAccessToken()).isEqualTo("new-access");
        assertThat(response.getRefreshToken()).isEqualTo("new-refresh");
    }

    @Test
    void refresh_withRevokedToken_shouldThrowUnauthorized() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("revoked-token");

        RefreshToken stored = RefreshToken.builder()
                .userId(1L)
                .token("revoked-token")
                .revoked(true)
                .expiresAt(LocalDateTime.now().plusDays(7))
                .build();

        when(refreshTokenRepository.findByToken("revoked-token")).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(AuthServiceException.class)
                .hasMessageContaining("revoked");
    }

    @Test
    void refresh_withExpiredToken_shouldThrowUnauthorized() {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("expired-token");

        RefreshToken stored = RefreshToken.builder()
                .userId(1L)
                .token("expired-token")
                .revoked(false)
                .expiresAt(LocalDateTime.now().minusDays(1))
                .build();

        when(refreshTokenRepository.findByToken("expired-token")).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(AuthServiceException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void validate_withValidToken_shouldReturnValidResponse() {
        ValidateTokenRequest request = new ValidateTokenRequest();
        request.setToken("valid-token");

        when(jwtService.validateToken("valid-token")).thenReturn(true);
        when(jwtService.extractUserId("valid-token")).thenReturn(1L);
        when(jwtService.extractRole("valid-token")).thenReturn(Role.USER);

        ValidateTokenResponse response = authService.validate(request);

        assertThat(response.isValid()).isTrue();
        assertThat(response.getUserId()).isEqualTo(1L);
        assertThat(response.getRole()).isEqualTo(Role.USER);
    }

    @Test
    void validate_withInvalidToken_shouldReturnInvalidResponse() {
        ValidateTokenRequest request = new ValidateTokenRequest();
        request.setToken("bad-token");

        when(jwtService.validateToken("bad-token")).thenReturn(false);

        ValidateTokenResponse response = authService.validate(request);

        assertThat(response.isValid()).isFalse();
        assertThat(response.getUserId()).isNull();
    }
}
