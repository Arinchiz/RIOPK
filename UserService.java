package com.mamamarket.service;

import com.mamamarket.dto.UserDTO;
import com.mamamarket.dto.RegistrationUserDTO;
import com.mamamarket.entity.User;
import com.mamamarket.exception.AppError;
import com.mamamarket.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder; // <-- Импортируем PasswordEncoder
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleService roleService;
    // --- ВОТ ИСПРАВЛЕНИЕ ---
    // Внедряем PasswordEncoder, а НЕ SecurityConfig
    private final PasswordEncoder passwordEncoder;
    // -----------------------

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Transactional
    public User createNewUser(RegistrationUserDTO registrationUserDto) {
        if (findByUsername(registrationUserDto.getUsername()).isPresent() || findByEmail(registrationUserDto.getEmail()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Пользователь с таким username или email уже существует");
        }
        User user = new User();
        user.setUsername(registrationUserDto.getUsername());
        user.setEmail(registrationUserDto.getEmail());
        // Используем внедренный passwordEncoder
        user.setPassword(passwordEncoder.encode(registrationUserDto.getPassword()));
        user.setName(registrationUserDto.getName());
        user.setPhone(registrationUserDto.getPhone());
        user.setBalance(BigDecimal.ZERO);
        user.setActive(true);

        String roleName = registrationUserDto.getRole();
        if ("SELLER".equals(roleName)) {
            user.setRoles(List.of(roleService.getSellerRole()));
            user.setSellerApproved(false); // Новые продавцы требуют одобрения
        } else {
            user.setRoles(List.of(roleService.getCustomerRole()));
            user.setSellerApproved(false);
        }

        return userRepository.save(user);
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        String.format("Пользователь '%s' не найден", username)
                ));

        List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());

        log.debug("Загрузка пользователя [{}], Роли: {}", username, authorities);

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                authorities
        );
    }

    // --- Методы для UserController ---

    public UserDTO findUserDtoById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));
        return convertToUserDTO(user);
    }

    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::convertToUserDTO)
                .collect(Collectors.toList());
    }

    @Transactional
    public UserDTO blockUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));
        user.setActive(false);
        return convertToUserDTO(userRepository.save(user));
    }

    @Transactional
    public UserDTO unblockUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));
        user.setActive(true);
        return convertToUserDTO(userRepository.save(user));
    }

    @Transactional
    public UserDTO approveSeller(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));
        if (!user.getRoles().stream().anyMatch(role -> role.getName().equals("ROLE_SELLER"))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Пользователь не является продавцом");
        }
        user.setSellerApproved(true);
        return convertToUserDTO(userRepository.save(user));
    }

    public UserDTO findByEmailDto(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));
        return convertToUserDTO(user);
    }

    @Transactional
    public UserDTO topUpBalance(String username, BigDecimal amount) {
        if (amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Сумма пополнения должна быть положительной");
        }
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Пользователь не найден"));
        user.setBalance(user.getBalance().add(amount));
        return convertToUserDTO(userRepository.save(user));
    }


    public UserDTO convertToUserDTO(User user) {
        return new UserDTO(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getName(),
                user.getPhone(),
                user.getBalance(),
                user.getRoles().stream().map(role -> role.getName()).collect(Collectors.toList()),
                user.isActive(),
                user.isSellerApproved()
        );
    }
}
