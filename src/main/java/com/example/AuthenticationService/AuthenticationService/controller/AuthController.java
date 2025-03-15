package com.example.AuthenticationService.AuthenticationService.controller;

import com.example.AuthenticationService.AuthenticationService.dto.AuthRequest;
import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;
import com.example.AuthenticationService.AuthenticationService.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
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
@Tag(name = "Auth Controller", description = "Контроллер для аутентификации и управления пользователями")
public class AuthController {
    @Autowired
    private AuthService service;
    
    @Autowired
    private AuthenticationManager authenticationManager;
    
    @PostMapping("/register")
    @Operation(summary = "Регистрация нового пользователя", description = "Создает новую учетную запись пользователя и возвращает токен аутентификации в случае успеха")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Пользователь успешно зарегистрирован"),
            @ApiResponse(responseCode = "422", description = "Не удалось зарегистрировать пользователя")
    })
    public ResponseEntity<String> addNewUser(
            @Parameter(description = "Параметры нового пользователя", required = true)
            @RequestBody UserCredential user,
            HttpServletResponse response
    ) {
        String password = user.getPassword();
        String result = service.saveUser(user);
    
        if ("Success".equals(result)) {
            return getToken(
                    new AuthRequest(
                            user.getId(),
                            user.getName(),
                            password
                    ),
                    response
            );
        }
    
        return ResponseEntity.status(422).body(result);
    }
    
    @PostMapping("/token")
    @Operation(summary = "Получить токен аутентификации", description = "Генерирует JWT токен при корректных учетных данных")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Токен успешно получен"),
            @ApiResponse(responseCode = "422", description = "Неверные учетные данные")
    })
    public ResponseEntity<String> getToken(
            @Parameter(description = "Учетные данные пользователя", required = true)
            @RequestBody AuthRequest authRequest,
            HttpServletResponse response
    ) {
        Long userId = service.getUserIdByName(authRequest.getUsername());
        authRequest.setId(userId);
    
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getUsername(),
                        authRequest.getPassword()
                )
        );
    
        if (authenticate.isAuthenticated()) {
            Cookie cookie = new Cookie("jwtAuth", "token");
            cookie.setHttpOnly(true);
            cookie.setPath("/api/authentication");
    
            response.addCookie(cookie);
            return ResponseEntity.ok(service.generateToken(authRequest.getUsername(), authRequest.getId()));
        } else {
            return ResponseEntity.status(422).body("Unauthorized");
        }
    }
    @GetMapping("/validate")
    @Operation(summary = "Валидация токена аутентификации", description = "Проверяет корректность и срок действия переданного JWT токена")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Токен валиден"),
            @ApiResponse(responseCode = "401", description = "Токен недействителен или отсутствует")
    })
    public String validateToken(
            @Parameter(description = "JWT токен для валидации", required = true)
            @RequestParam("token") String token
    ) {
        service.validateToken(token);
        return "Token is valid";
    }
}
