package com.duoc.backend;

import com.duoc.backend.user.User;
import com.duoc.backend.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Crea el usuario "prueba" con password "123456" (BCrypt) al iniciar el contexto
 * de test. Asi los tests de integracion (HttpRequestTest, PatientControllerIntegrationTest)
 * pueden autenticarse contra la BD H2 en memoria sin necesidad de scripts SQL externos.
 */
@Component
@Profile("test")
public class TestDataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(TestDataInitializer.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        if (userRepository.findByUsername("prueba") != null) {
            return;
        }
        User user = new User();
        user.setUsername("prueba");
        user.setEmail("prueba@test.com");
        user.setPassword(passwordEncoder.encode("123456"));
        user.setEnabled(true);
        userRepository.save(user);
        log.info("Usuario de prueba creado: prueba / 123456");
    }
}
