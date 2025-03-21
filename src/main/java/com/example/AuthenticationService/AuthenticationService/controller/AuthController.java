package com.example.AuthenticationService.AuthenticationService.controller;

import com.example.AuthenticationService.AuthenticationService.dto.AuthRequest;
import com.example.AuthenticationService.AuthenticationService.entity.UserCredential;
import com.example.AuthenticationService.AuthenticationService.entity.UserCredentialDTO;
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
    @Operation(summary = "Регистрация нового пользователя", description = "Создает новую учетную запись пользователя и возвращает токен аутентификации в cookie в случае успеха")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Пользователь успешно зарегистрирован"),
            @ApiResponse(responseCode = "422", description = "Не удалось зарегистрировать пользователя"),
            @ApiResponse(responseCode = "400", description = "Неверный формат данных (наличие пробела в начале/конце логина/пароля)"),
            @ApiResponse(responseCode = "500", description = "Ошибка сервера")
    })
    public ResponseEntity<String> addNewUser(
            @Parameter(description = "Параметры нового пользователя", required = true)
            @RequestBody UserCredentialDTO user,
            HttpServletResponse response
    ) {
        String password = user.getPassword();

        if(password.endsWith(" ") || password.startsWith(" ")) {
            return ResponseEntity.status(400).body("Password");
        }
        if(user.getName().startsWith(" ") || user.getName().endsWith(" ")) {
            return ResponseEntity.status(400).body("Login");
        }

        Long id = service.saveUser(user);

        if (id != -1L) {
            return getToken(
                    new AuthRequest(
                            user.getName(),
                            password
                    ),
                    response
            );
        }

        return ResponseEntity.status(422).body("Fail");
    }

    @PostMapping("/token")
    @Operation(summary = "Получить токен аутентификации (используется для входа пользователя)", description = "Генерирует JWT токен при корректных учетных данных и возвращает в cookie")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Токен успешно получен"),
            @ApiResponse(responseCode = "422", description = "Неверные учетные данные"),
            @ApiResponse(responseCode = "500", description = "Ошибка сервера")
    })
    public ResponseEntity<String> getToken(
            @Parameter(description = "Учетные данные пользователя", required = true)
            @RequestBody AuthRequest authRequest,
            HttpServletResponse response
    ) {
        Long userId = service.getUserIdByName(authRequest.getUsername());

        if(userId == -1L) {
            return ResponseEntity.status(422).body("No user with this credentials");
        }

        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getUsername(),
                        authRequest.getPassword()
                )
        );

        if (authenticate.isAuthenticated()) {
            String token = service.generateToken(authRequest.getUsername(), userId);

            Cookie cookie = new Cookie("jwtAuth", token);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(1000 * 60 * 60 * 10);

            response.addCookie(cookie);
            return ResponseEntity.ok("Ok");
        } else {
            return ResponseEntity.status(422).body("Unauthorized");
        }
    }
}
