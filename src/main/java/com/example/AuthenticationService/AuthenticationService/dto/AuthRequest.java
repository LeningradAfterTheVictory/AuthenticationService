package com.example.AuthenticationService.AuthenticationService.dto;

public class AuthRequest {

    private String name;
    private String password;

    public void setUsername(String name) {
        this.name = name;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getUsername() {
        return name;
    }

    public String getPassword() {
        return password;
    }
}
