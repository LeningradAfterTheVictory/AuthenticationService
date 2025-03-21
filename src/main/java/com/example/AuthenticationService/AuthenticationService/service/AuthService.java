package com.example.AuthenticationService.AuthenticationService.service;

import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;
import com.example.AuthenticationService.AuthenticationService.entity.UserCredentialDTO;
import com.example.AuthenticationService.AuthenticationService.repository.UserCredentialRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserCredentialRepository repository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    public Long saveUser(UserCredentialDTO credential) {
        credential.setPassword(passwordEncoder.encode(credential.getPassword()));

        return repository.save(credential);
    }

    public Long getUserIdByName(String name) {
        Optional<UserCredential> user = repository.findByNameOrEmail(name);

        if (user.isPresent()) {
            return user.get().getId();
        }

        return -1L;
    }

    public String generateToken(String username, Long id) {
        return jwtService.generateToken(username, id);
    }

    public void validateToken(String token) {
        jwtService.validateToken(token);
    }


}
