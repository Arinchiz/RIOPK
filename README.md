1 АРХИТЕКТУРА ПРОГРАММНОГО СРЕДСТВА В НОТАЦИИ С4

Контейнерный уровень архитектуры программного средства представлен на рисунке 1.

<img width="424" height="395" alt="image" src="https://github.com/user-attachments/assets/d97492fd-881e-4a9d-918e-fa29d49c08bc" />

  Рисунок 1 – Контейнерный уровень архитектуры программного средства 

В основе программного средства реализации веб-сервиса заказа потребительских товаров для мам и детей находится веб-приложение, созданное с использованием JavaScript и Angular. Оно обеспечивает удобный интерфейс для пользователей: просмотр каталога товаров, добавление товаров в корзину, оформление заказов, написание отзывов и получение уведомлений о состоянии покупок.
Для обработки действий пользователей работает серверное API-приложение, разработанное на Java с использованием Spring Boot и Spring MVC. Оно предоставляет функционал системы через REST API, включая управление пользователями, товарами, корзиной, заказами, платежами и уведомлениями. API-приложение обрабатывает запросы и взаимодействует с базой данных через контроллеры и сервисные компоненты.
Хранилище данных реализовано на MySQL и содержит информацию о пользователях, товарах, корзинах, заказах, платежах, уведомлениях и отзывах. База данных обеспечивает надёжное хранение и актуализацию информации, необходимой для работы API, корректного отображения данных в веб-приложении и формирования аналитики по заказам и отзывам.
Компонентный уровень архитектуры программного средства представлен на рисунке 2.

<img width="468" height="392" alt="image" src="https://github.com/user-attachments/assets/2a0ddb96-57a2-41eb-8cb4-3498e44f3d7a" />

Рисунок 2 – Компонентный уровень архитектуры программного средства 

API-приложение, разработанное на Java с использованием Spring Boot и Spring MVC, было детализировано на уровне компонентов — каждый компонент (контроллер) отвечает за отдельную функциональность системы. Веб-приложение на JavaScript и Angular взаимодействует с контроллерами через REST API.
	UserController отвечает за управление пользователями: регистрацию, вход в систему, обновление профиля и получение истории заказов. Обрабатывает запросы веб-приложения и передаёт их в соответствующий сервис.
	ProductController управляет товарами: просмотр каталога, добавление новых товаров, обновление существующих и удаление. Обеспечивает взаимодействие веб-приложения с бизнес-логикой и базой данных через сервис.
 	CartController обрабатывает операции с корзиной: добавление и удаление товаров, просмотр содержимого и расчёт общей суммы. Взаимодействует с сервисами корзины и товаров.
 	OrderController управляет заказами: создание, обновление, просмотр статуса и отмена заказов. Получает данные из корзины и передаёт их в сервис дляробработки.
 	PaymentController обеспечивает процесс оплаты заказов: инициирование платежа, подтверждение и проверка статуса. Взаимодействует с внешними платёжными системами через сервис. Интегрируется с внешней платёжной системой PayPal через сервисный слой.
NotificationController отвечает за уведомления пользователей о статусе заказов и других событиях. Отправка уведомлений осуществляется через внешнюю платформу Firebase, а информация о доставленных уведомлениях хранится в журнале через сервисный слой.
ReviewController управляет отзывами на товары: добавление и редактирование отзывов. Обеспечивает связь между пользователями и товарамирчерез сервисный слой.
Вся информация о пользователях, товарах, корзинах, заказах, платежах, уведомлениях и отзывах хранится в MySQL. База данных обеспечивает надёжное хранение и доступ для всех компонентов API-приложения, поддерживает корректное отображение данных в веб-приложении и работу аналитики.
Кодовый уровень архитектуры программного средства представлен на рисунке 3.

<img width="185" height="305" alt="image" src="https://github.com/user-attachments/assets/cb914e86-69ce-4c1d-94ee-8c95f3ad89c1" />

Рисунок 3 – Кодовый уровень архитектуры программного средства 

Кодовый уровень архитектуры отражает структуру классов, реализующих бизнес-логику приложения. В центре модели находится класс User, содержащий ключевые атрибуты: идентификатор (id), имя (name), электронную почту (email) и пароль (password). Этот класс связан с классами Cart, Order, Review и Notification, что позволяет отслеживать содержимое корзины пользователя, оформленные заказы, оставленные отзывы и полученные уведомления.
Класс Cart хранит товары, добавленные пользователем, и вычисляет итоговую стоимость заказа. Он связан с классом Product, представляющим товары, и используется для формирования заказа через класс Order. Класс Order управляет оформлением заказов, включая идентификатор заказа, дату, статус и связь с пользователем, а также связан с классом Payment, который отвечает за обработку оплаты заказа. Класс Payment хранит сумму, статус, метод оплаты и связь с заказом, при этом для проведения платежей интегрируется с внешней платёжной системой PayPal.
Класс Product содержит атрибуты товара, такие как идентификатор, название, описание, цену и количество на складе. Он связан с классом Cart для добавления товаров в корзину и с классом Review, позволяющим пользователям оставлять отзывы о товарах. Класс Review хранит идентификатор отзыва, ссылку на пользователя и товар, текст отзыва и рейтинг, обеспечивая связь пользователей с продуктами.
Класс Notification хранит уведомления для пользователей, включая идентификатор, ссылку на пользователя, текст сообщения, дату и статус уведомления. Для отправки уведомлений класс интегрирован с внешней системой Firebase.
Основные связи между классами включают: пользователь может иметь одну корзину, множество заказов, множество отзывов и множество уведомлений; корзина может содержать множество товаров, а один товар может находиться в корзинах разных пользователей; одна корзина преобразуется в один заказ, а заказ связан с одним платежом; один продукт может иметь множество отзывов. Такая структура классов обеспечивает полное покрытие функциональности системы, включая управление пользователями, товарами, корзиной, заказами, оплатой, уведомлениями и отзывами.

2 СИСТЕМА ДИЗАЙНА ПОЛЬЗОВАТЕЛЬСКОГО ИНТЕРФЕЙСА

UI Kit программного средства представлен на рисунке 4.

<img width="479" height="263" alt="image" src="https://github.com/user-attachments/assets/02bc932d-6a8e-41ff-bc7a-c545ebe2e67f" />

Рисунок 4 – UI Kit программного средства 

Цветовая гамма будет в оттенках сиреневого, черного, серого и белого. Поля ввода, фильтров и поиска будут в светло-сером цвете с темно-серыми надписями. Основным стилем текста будет Inria Sans. Статусы заказов представлены в зеленом, красном, синем цветах, а процессы загрузки в фиолетовом.

3 АРХИТЕКТУРА

![telegram-cloud-photo-size-2-5431559425598030584-y](https://github.com/user-attachments/assets/fa439702-4bb5-4075-be30-74058ff0807b)

На рисунке 1 представлена диаграмма классов.

uml

Рисунок 1 – Диаграмма классов

	На рисунке 2 представлена диаграмма вариантов использования.
 <img width="468" height="346" alt="image" src="https://github.com/user-attachments/assets/2a50039d-095e-4d86-8ff1-555e2e53f0b3" />

Рисунок 2 – Диаграмма вариантов использования

	На рисунке 3 представлена диаграмма состояния обработки заказа.

 <img width="221" height="401" alt="image" src="https://github.com/user-attachments/assets/6fc345f2-5b1b-46b5-a3b7-b230d91d84c2" />

Рисунок 3 – Диаграмма состояния обработки заказа

На рисунке 4 представлена диаграмма последовательности варианта использования "Оформить товар". 

<img width="468" height="296" alt="image" src="https://github.com/user-attachments/assets/070e58ec-8064-4dcb-b9bb-857eb873a1fd" />

Рисунок 4 – Диаграмма последовательности варианта использования "Оформить товар"

На рисунке 5 представлена диаграмма развертывания. 

<img width="412" height="287" alt="image" src="https://github.com/user-attachments/assets/068c5f64-56d0-412b-a5ee-bbd8f562c30a" />
 
Рисунок 5 – Диаграмма развертывания



4 ПОЛЬЗОВАТЕЛЬСКИЙ ИНТЕРФЕЙС

4.1 Примеры экранов UI

На рисунке 1 представлена главная страница программного средства.

 ![image](https://github.com/user-attachments/assets/167dbbd9-5e8b-45b0-aa7e-43a4675faf15)

Рисунок 1 – Главная страница

На рисунке 2 представлена страница «Продукты».
 ![image](https://github.com/user-attachments/assets/4859406f-d70a-4172-ac19-c94f73d2413e)

Рисунок 2 – Страница «Продукты»

На рисунке 3 представлена страница «Корзина».

![image](https://github.com/user-attachments/assets/5b3fc7f2-0bf9-48bc-8586-cce3328d5ccc)

Рисунок 3 – Страница «Корзина»

На рисунке 4 представлена страница «Профиль».
 ![image](https://github.com/user-attachments/assets/6c47006b-8a08-42a9-a945-5370eff677be)

Рисунок 4 – Страница «Профиль»

На рисунке 5 представлена страница добавления товара.

 ![image](https://github.com/user-attachments/assets/313cab7e-9cf5-4edb-9f60-477b3985cda9)

Рисунок 5 – Страница добавления товара

На рисунке 6 представлена страница «Избранное».

![image](https://github.com/user-attachments/assets/89a15904-b866-47e1-80a2-e789040f8b18)

Рисунок 6 – Страница «Избранное»

На рисунке 7 представлена страница карточки товара.

![image](https://github.com/user-attachments/assets/e996f04f-bba8-41c1-881c-bc99f4a4864d)

Рисунок 7 – Страница карточки товара

На рисунке 8 представлена страница управления пользователями.

![image](https://github.com/user-attachments/assets/7cb71c24-e616-4b43-87f4-977d21c15ca8)

Рисунок 8 – Страница управления пользователями

На рисунке 9 представлена страница аналитики.

![image](https://github.com/user-attachments/assets/f4af503f-57d5-41b4-a4da-0d8d2a48432a)

Рисунок 9 – Страница аналитики

4 БЕЗОПАСНОСТЬ

Для реализации системы безопасности были использованы следующие сторонние компоненты, входящие в экосистему Spring:
1) Spring Security (Starter): spring-boot-starter-security - Основной фреймворк, взявший на себя управление фильтрами безопасности, аутентификацией и авторизацией.
2) JSON Web Tokens (JWT): io.jsonwebtoken:jjwt-api - Выбран для реализации stateless-аутентификации. Это позволяет серверу не хранить сессию для каждого пользователя, что упрощает масштабирование. Клиент (веб-приложение) получает токен при входе и прикрепляет его к каждому последующему запросу.
3) Spring Security Crypto: spring-security-crypto - Использован для реализации механизма шифрования (хеширования) паролей пользователей перед сохранением в базу данных.
Реализация механизма авторизации
Авторизация (проверка "что тебе можно делать") реализована на двух уровнях:
a) Уровень фильтров (Общая конфигурация безопасности)
Создан компонент JwtRequestFilter, который выполняется перед каждым запросом (кроме публичных). Его задача — прочитать токен из заголовка Authorization, валидировать его и загрузить данные пользователя в SecurityContextHolder.

package com.mamamarket.config;

import com.mamamarket.utils.JwtTokenUtils;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtTokenUtils jwtTokenUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            try {
                username = jwtTokenUtils.getUsername(jwt);
            } catch (ExpiredJwtException e) {
                log.debug("Время жизни токена вышло");
                // Можно отправить кастомный ответ, если нужно
                // response.setStatus(HttpStatus.UNAUTHORIZED.value());
                // response.getWriter().write("Token expired");
                // return;
            } catch (Exception e) {
                log.debug("Ошибка парсинга токена");
            }
        }
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            List<String> roles = jwtTokenUtils.getRoles(jwt);

            log.info("Роли из токена: {}", roles);

            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
            );
            SecurityContextHolder.getContext().setAuthentication(token);
        }
        filterChain.doFilter(request, response);
    }
}

Механизмы обеспечения безопасности данных
a) Шифрование (Хеширование) паролей
В соответствии с заданием, реализован механизм шифрования. Пароли пользователей никогда не хранятся в открытом виде. При регистрации пароль хешируется с использованием BCryptPasswordEncoder.
BCrypt — это адаптивная хеш-функция, которая включает "соль" (salt) и "фактор стоимости" (work factor), что делает ее крайне устойчивой к атакам перебором (brute-force) и по радужным таблицам.
Пример кода (Хеширование при регистрации)

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
На рисунке 1 отображен пример хеширования при регистрации.

 ![image](https://github.com/user-attachments/assets/3238eef4-df5f-4c93-93e6-b3cedc9b3f79)

Рисунок 1 – Хеширование при регистрации

