package ru.romanov.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class T1DebutAuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(T1DebutAuthServiceApplication.class, args);
    }

}
