package com.kibuti.oauth2server.Utils;

import com.kibuti.oauth2server.entity.User;
import com.kibuti.oauth2server.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        // Check if we need to create a default admin user
        if (userRepository.count() == 0) {
            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setPassword(passwordEncoder.encode("admin123"));
            adminUser.setEmail("admin@example.com");
            adminUser.setFullName("Admin User");
            adminUser.setEnabled(true);

            Set<String> roles = new HashSet<>();
            roles.add("ADMIN");
            roles.add("USER");
            adminUser.setRoles(roles);

            userRepository.save(adminUser);

            System.out.println("Created default admin user: admin / admin123");
        }
    }
}