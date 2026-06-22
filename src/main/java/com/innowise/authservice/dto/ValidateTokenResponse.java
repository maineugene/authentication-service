package com.innowise.authservice.dto;

import com.innowise.authservice.model.Role;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ValidateTokenResponse {

    private boolean valid;
    private Long userId;
    private Role role;
}
