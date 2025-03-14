package com.example.AuthenticationService.AuthenticationService.repository;

import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;

import java.util.Optional;

public interface UserCredentialRepository {
    Optional<UserCredential> findByNameOrEmail(String username);
    String save(UserCredential userCredential);
}
