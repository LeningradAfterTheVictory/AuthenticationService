package com.example.AuthenticationService.AuthenticationService.dto;

public class AuthRequest {

    private Long id;
    private String name;
    private String password;

    public void setId(Long id) {
      this.id = id;
    }

    public void setUsername(String name) {
        this.name = name;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return name;
    }

    public String getPassword() {
        return password;
    }
}
