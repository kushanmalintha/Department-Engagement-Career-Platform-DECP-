package com.decp.auth_service.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    /**
     * Test endpoint — accessible ONLY by ADMIN role.
     * Protected by SecurityConfig: .requestMatchers("/api/admin/**").hasRole("ADMIN")
     */
    @GetMapping("/test")
    public String adminTest(Authentication authentication) {
        return "Admin access confirmed for: " + authentication.getName();
    }
}
