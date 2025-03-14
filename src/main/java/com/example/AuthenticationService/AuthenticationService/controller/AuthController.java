package com.example.AuthenticationService.AuthenticationService.controller;

import com.example.AuthenticationService.AuthenticationService.dto.AuthRequest;
import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;
import com.example.AuthenticationService.AuthenticationService.service.AuthService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/authentication")
public class AuthController {
    @Autowired
    private AuthService service;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<String> addNewUser(@RequestBody UserCredential user) {
        String result = service.saveUser(user);

        if(result.equals("Success")) {
            return ResponseEntity.ok(result);
        }

        return ResponseEntity.status(422).body(result);
    }

    @PostMapping("/token")
    public ResponseEntity<String> getToken(@RequestBody AuthRequest authRequest, HttpServletResponse response) {
        UserCredential userCredential = service.findByUsername(authRequest.getUsername());

        if (userCredential != null && userCredential.getEmail().equals(authRequest.getEmail())) {
            Authentication authenticate = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );

            if (authenticate.isAuthenticated()) {
                Cookie cookie = new Cookie("jwtAuth", "token");
                cookie.setHttpOnly(true);
                cookie.setPath("/api/authentication");

                response.addCookie(cookie);
                return ResponseEntity.ok(service.generateToken(authRequest.getUsername(), authRequest.getId()));
            }
        }
        return ResponseEntity.status(422).body("Unauthorized");
    }

    @GetMapping("/validate")
    public String validateToken(@RequestParam("token") String token) {
        service.validateToken(token);
        return "Token is valid";
    }
}
