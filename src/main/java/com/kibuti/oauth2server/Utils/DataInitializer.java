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
        // Check if we need to create default users
        if (userRepository.count() == 0) {
            // Create admin user
            User adminUser = new User();
            adminUser.setUsername("admin");
            adminUser.setPassword(passwordEncoder.encode("admin123"));
            adminUser.setEmail("admin@example.com");
            adminUser.setFullName("Admin User");
            adminUser.setEnabled(true);

            Set<String> adminRoles = new HashSet<>();
            adminRoles.add("ADMIN");
            adminRoles.add("USER");
            adminUser.setRoles(adminRoles);

            userRepository.save(adminUser);
            System.out.println("Created default admin user: admin / admin123");

            // Create regular user
            User regularUser = new User();
            regularUser.setUsername("user");
            regularUser.setPassword(passwordEncoder.encode("password"));
            regularUser.setEmail("user@example.com");
            regularUser.setFullName("Regular User");
            regularUser.setEnabled(true);

            Set<String> userRoles = new HashSet<>();
            userRoles.add("USER");
            regularUser.setRoles(userRoles);

            userRepository.save(regularUser);
            System.out.println("Created default regular user: user / password");
        }
    }
}