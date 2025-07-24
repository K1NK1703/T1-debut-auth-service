# 🔐 Сервис аутентификации и авторизации пользователей

Полнофункциональный REST API сервис аутентификации и авторизации на Spring Boot с JWT токенами, системой ролей и PostgreSQL базой данных.


## Содержание

- Возможности  
- Стек технологий  
- Конфигурация  
- Тестирование  
- Развёртывание  
- Примеры использования


## Возможности

- Регистрация и аутентификация пользователей  
- JWT токены с ограниченным временем жизни (1 час)  
- Refresh токены для обновления доступа без повторного ввода пароля (7 дней)  
- Система ролей: `ADMIN`, `PREMIUM_USER`, `GUEST`  
- Отзыв токенов (logout, revoke)  
- Шифрование паролей с BCrypt  
- Валидация данных с подробными сообщениями об ошибках  
- Управление пользователями (только для админов)  


## Стек технологий

- Java 23  
- Spring Boot 3.5.3  
- Spring Security 6.x  
- Spring Data JPA  
- PostgreSQL 17  
- JWT (jjwt 0.12.6)  
- Docker & Docker Compose  
- Maven  
- Lombok  


## Конфигурация

```env
SERVER_PORT=8200
SPRING_PROFILES_ACTIVE=local

DB_URL=postgres
DB_PORT=5450
DB_NAME=authdb
DB_USERNAME=postgres
DB_PASSWORD=postgres

JWT_SECRET_KEY=myVerySecretJWTKey123456789012345678901234567890abcdef
```

---

## Тестирование

В базе при запуске создаются пользователи:

```
{
  "login": "admin",
  "password": "123456789", # (пароль хранится в закодированном состоянии)
  "roles": ['ADMIN', 'PREMIUM_USER', 'GUEST'],
  другие атрибуты...
}

{
  "login": "premium_user",
  "password": "123456789", # (пароль хранится в закодированном состоянии)
  "roles": ['PREMIUM_USER', 'GUEST'],
  другие атрибуты...
}

{
  "login": "guest",
  "password": "123456789", # (пароль хранится в закодированном состоянии)
  "roles": ['GUEST'],
  другие атрибуты...
}
```

## Развёртывание

1. Клонировать репозиторий
2. Открыть Docker
3. Открыть проект в IDE
4. Проверить параметры .env файла
5. Запустить проект

## Примеры использования

1. Login: POST http://localhost:8200/auth/login
Headers: Content-type: application/json
Body:
```
{
    "login": "admin",
    "password": "123456789"
}
```
Ответ: 200 OK
```
json:
{
    "access_token": "eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbInByZW1pdW1fdXNlciIsImFkbWluIiwiZ3Vlc3QiXSwiaWF0IjoxNzUzMzYwNjkwLCJleHAiOjE3NTMzNjQyOTB9.XBnHZBdYkeMmvs4jV3bHfPyM7lxP75NonG-Pmhuqgj36huD0uuaiFPrM2Nu9DTWS",
    "refresh_token": "60a2d50e-2950-4b50-823a-9387de9035fb",
    "tokenType": "Bearer",
    "expires_at": [
        2025,
        7,
        24,
        16,
        38,
        10,
        838524500
    ],
    "user": {
        "id": 1,
        "login": "admin",
        "email": "admin@mail.ru",
        "roles": [
            "PREMIUM_USER",
            "GUEST",
            "ADMIN"
        ]
    }
}
```

2. Logout: POST http://localhost:8200/auth/logout
Authorization: Bearer Token
```
Token: eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbInByZW1pdW1fdXNlciIsImFkbWluIiwiZ3Vlc3QiXSwiaWF0IjoxNzUzMzYwNjkwLCJleHAiOjE3NTMzNjQyOTB9.XBnHZBdYkeMmvs4jV3bHfPyM7lxP75NonG-Pmhuqgj36huD0uuaiFPrM2Nu9DTWS
```
Ответ: 200 OK
```
json:
{
    "success": true,
    "message": "Успешный выход из системы",
    "data": null
}
```

3. Другие endpoint's:
```
  POST	/auth/login	    Логин (получение JWT токенов)
  POST	/auth/register	Регистрация нового пользователя
  POST	/auth/refresh	  Обновление (рефреш) JWT токена
  POST	/auth/logout	  Выход (отзыв токена/разлогин)
  POST  /auth/revoke    Отозвать все токены
  GET   /admin/users    Список всех пользователей
  GET   /user/profile   Профиль пользователя
  PUT   /user/profile   Обновить профиль
```
