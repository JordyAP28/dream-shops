package com.dailycodework.dreamshops.data;
import com.dailycodework.dreamshops.model.Role;
import com.dailycodework.dreamshops.model.User;
import com.dailycodework.dreamshops.repository.RoleRepository;
import com.dailycodework.dreamshops.repository.UserRepository;
import com.dailycodework.dreamshops.response.ApiResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.UserRoleAuthorizationInterceptor;

import java.util.Set;

@Transactional
@Component
@RequiredArgsConstructor
public class DataInitializer implements ApplicationListener <ApplicationReadyEvent> {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        Set<String> defaultRoles = Set.of("ROLE_ADMIN", "ROLE_USER");
        createDefaultUserIfNotExists();
        createDefaultRoleIfNotExists(defaultRoles);
        createDefaultAdminIfNotExists();
    }
    private void createDefaultUserIfNotExists() {
        roleRepository.findByName("ROLE_USER").ifPresentOrElse(userRole -> {
            for (int i = 1; i <= 5; i++) {
                String defaultEmail = "user" + i + "@email.com";
                if (userRepository.existsByEmail(defaultEmail)) {
                    continue;
                }
                User user = new User();
                user.setFirstName("The User");
                user.setLastName("User" + i);
                user.setEmail(defaultEmail);
                user.setPassword(passwordEncoder.encode("123456"));
                user.setRoles(Set.of(userRole));
                userRepository.save(user);
                System.out.println("Default vet user " + i + " created successfully.");
            }
        }, () -> {
            throw new IllegalStateException("ROLE_USER not found in the database. Please ensure roles are initialized correctly.");
        });
    }

    private void createDefaultAdminIfNotExists() {
        roleRepository.findByName("ROLE_ADMIN").ifPresentOrElse(adminRole -> {
            for (int i = 1; i <= 2; i++) {
                String defaultEmail = "admin" + i + "@email.com";
                if (userRepository.existsByEmail(defaultEmail)) {
                    continue;
                }
                User user = new User();
                user.setFirstName("Admin");
                user.setLastName("Admin" + i);
                user.setEmail(defaultEmail);
                user.setPassword(passwordEncoder.encode("123456"));
                user.setRoles(Set.of(adminRole));
                userRepository.save(user);
                System.out.println("Default admin user " + i + " created successfully.");
            }
        }, () -> {
            throw new IllegalStateException("ROLE_ADMIN not found in the database. Please ensure roles are initialized correctly.");
        });
    }

    private void createDefaultRoleIfNotExists(Set<String> roles) {
        roles.stream()
                .filter(role -> roleRepository.findByName(role).isEmpty())
                .map(Role::new).forEach(roleRepository::save);
    }
}

