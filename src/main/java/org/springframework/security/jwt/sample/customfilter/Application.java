package org.springframework.security.jwt.sample.customfilter;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jwt.sample.customfilter.domain.Role;
import org.springframework.security.jwt.sample.customfilter.domain.User;
import org.springframework.security.jwt.sample.customfilter.repository.UserRepository;

import java.util.Arrays;
import java.util.List;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InitializingBean addUsers() {

        return new InitializingBean() {

            @Autowired
            private PasswordEncoder passwordEncoder;

            @Autowired
            private UserRepository userRepository;

            @Override
            public void afterPropertiesSet() {
                addUser("admin", "pwd", Arrays.asList(Role.ROLE_ADMIN, Role.ROLE_USER));
                addUser("user", "pwd", Arrays.asList(Role.ROLE_USER));
            }

            private void addUser(String username, String password, List<Role> roles) {
                User user = new User();
                user.setUsername(username);
                user.setPassword(passwordEncoder.encode(password));
                user.setRoles(roles);
                user.setEnabled(true);
                user.setLocked(false);
                userRepository.save(user);
            }
        };
    }
}
