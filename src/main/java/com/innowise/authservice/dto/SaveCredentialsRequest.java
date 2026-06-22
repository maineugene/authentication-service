package com.innowise.authservice.dto;

import com.innowise.authservice.model.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class SaveCredentialsRequest {

    @NotNull
    private Long userId;

    @NotBlank
    private String login;

    @NotBlank
    private String password;

    @NotNull
    private Role role;
}
