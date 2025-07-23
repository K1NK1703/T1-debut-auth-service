INSERT INTO authdb.public.users (login, password, email, created_at, updated_at)
VALUES
    ('admin', '$2a$12$L7cyVPxdPhIsrbxnOOrxVuxENM6fj6xh4aTVIBFnjCRWj063BoakC', 'admin@mail.ru', NOW(), NOW()),
    ('guest', '$2a$12$L7cyVPxdPhIsrbxnOOrxVuxENM6fj6xh4aTVIBFnjCRWj063BoakC', 'guest@mail.ru', NOW(), NOW()),
    ('premium_user', '$2a$12$L7cyVPxdPhIsrbxnOOrxVuxENM6fj6xh4aTVIBFnjCRWj063BoakC', 'premiumuser@mail.ru', NOW(), NOW());

INSERT INTO authdb.public.user_roles (user_id, roles)
VALUES
    (1, 'ADMIN'),
    (2, 'GUEST'),
    (3, 'PREMIUM_USER'),
    (1, 'PREMIUM_USER'),
    (1, 'GUEST')