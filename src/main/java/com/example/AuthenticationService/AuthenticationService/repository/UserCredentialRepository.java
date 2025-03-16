package com.example.AuthenticationService.AuthenticationService.repository;

import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;
import com.example.AuthenticationService.AuthenticationService.entity.UserCredentialDTO;

import java.util.Optional;

public interface UserCredentialRepository {
    Optional<UserCredential> findByNameOrEmail(String username);
    Long save(UserCredentialDTO userCredential);
}
