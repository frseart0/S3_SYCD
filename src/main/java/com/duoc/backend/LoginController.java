package com.duoc.backend;
import com.duoc.backend.JWTAuthenticationConfig;
import com.duoc.backend.user.MyUserDetailsService;
import com.duoc.backend.user.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder; // Nuevo import
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @Autowired
    JWTAuthenticationConfig jwtAuthtenticationConfig;

    @Autowired
    private MyUserDetailsService userDetailsService;

    // --- INYECTAMOS EL ENCRIPTADOR ---
    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/")
    public String inicio() {
        return "Bienvenido al catálogo público de mascotas";
    }

    @PostMapping("login")
    public String login(@RequestBody User loginRequest) {

        final UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());

        // --- SOLUCIÓN: COMPARACIÓN SEGURA CON BCRYPT ---
        if (!passwordEncoder.matches(loginRequest.getPassword(), userDetails.getPassword())) {
            throw new RuntimeException("Invalid login");
        }

        String token = jwtAuthtenticationConfig.getJWTToken(loginRequest.getUsername());
        return token;
    }
}