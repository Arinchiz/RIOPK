package com.mamamarket.controller;

import com.mamamarket.dto.JwtRequest;
import com.mamamarket.dto.RegistrationUserDTO;
import com.mamamarket.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // Эндпоинт для входа
    @PostMapping("/auth")
    public ResponseEntity<?> createAuthToken(@RequestBody JwtRequest authRequest) {
        return authService.createAuthToken(authRequest);
    }

    // Эндпоинт для регистрации
    // @Valid включает проверку аннотаций из RegistrationUserDTO
    @PostMapping("/registration")
    public ResponseEntity<?> createNewUser(@Valid @RequestBody RegistrationUserDTO registrationUserDTO) {
        return authService.createNewUser(registrationUserDTO);
    }
}
