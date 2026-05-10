package com.duoc.backend;
import com.duoc.backend.user.MyUserDetailsService;
import com.duoc.backend.user.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class LoginController {

    @Autowired
    JWTAuthenticationConfig jwtAuthtenticationConfig;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/")
    public String inicio() {
        return "Bienvenido al catálogo público de mascotas";
    }

    @PostMapping("login")
    public String login(@RequestBody User loginRequest) {
        final UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
        } catch (UsernameNotFoundException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid login");
        }

        if (!passwordEncoder.matches(loginRequest.getPassword(), userDetails.getPassword())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid login");
        }

        return jwtAuthtenticationConfig.getJWTToken(loginRequest.getUsername());
    }
}