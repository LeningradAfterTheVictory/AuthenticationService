package com.example.AuthenticationService.AuthenticationService.repository;

import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;

import java.util.Optional;

public interface UserCredentialRepository {
    Optional<UserCredential> findByName(String username);
    Optional<UserCredential> findById(Long id);
    Optional<UserCredential> findByEmail(String email);
    String save(UserCredential userCredential);
    String getRoleForUser(String userName);
}
