package com.example.userservice.vo;

import jakarta.validation.constraints.Size;
import lombok.Data;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;

@Data
public class RequestUser {

    @NotNull(message = "Email cannot be null")
    @Size(min = 2, message = "Email must be at least two characters")
    @Email(message = "Email should be valid")
    private String email;

    @NotNull(message = "Name cannot be null")
    @Size(min = 2, message = "Name must be at least two characters")
    private String name;

    @NotNull(message = "Password cannot be null")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String pwd;
}
