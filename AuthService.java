package com.mamamarket.service;

import com.mamamarket.dto.JwtRequest;
import com.mamamarket.dto.JwtResponse;
import com.mamamarket.dto.RegistrationUserDTO;
import com.mamamarket.dto.UserDTO;
import com.mamamarket.entity.Role;
import com.mamamarket.entity.User;
import com.mamamarket.exception.AppError;
import com.mamamarket.repository.UserRepository;
import com.mamamarket.utils.JwtTokenUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserRepository userRepository;
    private final JwtTokenUtils jwtTokenUtils;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    public ResponseEntity<?> createAuthToken(JwtRequest authRequest) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(new AppError(HttpStatus.UNAUTHORIZED.value(), "Неверный логин или пароль"), HttpStatus.UNAUTHORIZED);
        }

        User user = userRepository.findByUsername(authRequest.getUsername())
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));

        // Проверка, активен ли пользователь
        if (!user.isActive()) {
            return new ResponseEntity<>(new AppError(HttpStatus.FORBIDDEN.value(), "Пользователь заблокирован"), HttpStatus.FORBIDDEN);
        }

        // Если это SELLER, проверяем, подтвержден ли он
        List<String> roles = user.getRoles().stream().map(Role::getName).collect(Collectors.toList());
        if (roles.contains("ROLE_SELLER") && !user.isSellerApproved()) {
            return new ResponseEntity<>(new AppError(HttpStatus.FORBIDDEN.value(), "Аккаунт продавца находится на модерации"), HttpStatus.FORBIDDEN);
        }

        UserDetails userDetails = userService.loadUserByUsername(authRequest.getUsername());
        String token = jwtTokenUtils.generateToken(userDetails);

        return ResponseEntity.ok(new JwtResponse(token, roles));
    }

    public ResponseEntity<?> createNewUser(RegistrationUserDTO registrationUserDTO) {
        if (userService.findByUsername(registrationUserDTO.getUsername()).isPresent() ||
                userService.findByEmail(registrationUserDTO.getEmail()).isPresent()) {
            return new ResponseEntity<>(new AppError(HttpStatus.BAD_REQUEST.value(), "Пользователь с указанными данными уже существует"), HttpStatus.BAD_REQUEST);
        }
        User user = userService.createNewUser(registrationUserDTO);

        // Возвращаем полный UserDTO
        return ResponseEntity.ok(userService.convertToUserDTO(user));
    }
}
