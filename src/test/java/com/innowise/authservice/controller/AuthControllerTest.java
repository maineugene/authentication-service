package com.innowise.authservice.controller;

import com.innowise.authservice.dto.LoginRequest;
import com.innowise.authservice.dto.RefreshTokenRequest;
import com.innowise.authservice.dto.SaveCredentialsRequest;
import com.innowise.authservice.dto.TokenResponse;
import com.innowise.authservice.dto.ValidateTokenRequest;
import com.innowise.authservice.dto.ValidateTokenResponse;
import com.innowise.authservice.exception.AuthServiceException;
import com.innowise.authservice.model.Role;
import com.innowise.authservice.service.impl.AuthServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.service.impl.JwtServiceImpl;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @MockitoBean
    private AuthServiceImpl authService;

    @MockitoBean
    private JwtServiceImpl jwtService;

    @TestConfiguration
    static class TestSecurityConfig {
        @Bean
        SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http.csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers("/api/auth/token", "/api/auth/validate", "/api/auth/refresh").permitAll()
                            .requestMatchers("/api/auth/credentials").hasRole("ADMIN")
                            .anyRequest().authenticated()
                    );
            return http.build();
        }
    }

    @Test
    void login_withValidCredentials_shouldReturn200() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setLogin("john");
        request.setPassword("password");

        when(authService.login(any())).thenReturn(new TokenResponse("access", "refresh"));

        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access"))
                .andExpect(jsonPath("$.refreshToken").value("refresh"));
    }

    @Test
    void login_withInvalidCredentials_shouldReturn401() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setLogin("john");
        request.setPassword("wrong");

        when(authService.login(any())).thenThrow(new AuthServiceException("Invalid login or password", HttpStatus.UNAUTHORIZED));

        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid login or password"));
    }

    @Test
    void login_withMissingFields_shouldReturn400() throws Exception {
        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void validate_withValidToken_shouldReturn200() throws Exception {
        ValidateTokenRequest request = new ValidateTokenRequest();
        request.setToken("valid-token");

        when(authService.validate(any())).thenReturn(new ValidateTokenResponse(true, 1L, Role.USER));

        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").value(1));
    }

    @Test
    void refresh_withValidRefreshToken_shouldReturn200() throws Exception {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("refresh-token");

        when(authService.refresh(any())).thenReturn(new TokenResponse("new-access", "new-refresh"));

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access"));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    void saveCredentials_asAdmin_shouldReturn201() throws Exception {
        SaveCredentialsRequest request = new SaveCredentialsRequest();
        request.setUserId(1L);
        request.setLogin("john");
        request.setPassword("password");
        request.setRole(Role.USER);

        doNothing().when(authService).saveCredentials(any());

        mockMvc.perform(post("/api/auth/credentials")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated());
    }

    @Test
    @WithMockUser(roles = "USER")
    void saveCredentials_asUser_shouldReturn403() throws Exception {
        SaveCredentialsRequest request = new SaveCredentialsRequest();
        request.setUserId(1L);
        request.setLogin("john");
        request.setPassword("password");
        request.setRole(Role.USER);

        mockMvc.perform(post("/api/auth/credentials")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }
}