package com.example.AuthenticationService.AuthenticationService.service;

import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;
import com.example.AuthenticationService.AuthenticationService.repository.UserCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private UserCredentialRepository repository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    public String saveUser(UserCredential credential) {
        credential.setPassword(passwordEncoder.encode(credential.getPassword()));
        repository.save(credential);
        return "user added to the system";
    }

    public String generateToken(String username, Long id) {
        return jwtService.generateToken(username, id);
    }

    public void validateToken(String token) {
        jwtService.validateToken(token);
    }


}
