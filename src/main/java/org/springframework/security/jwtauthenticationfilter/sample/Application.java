package org.springframework.security.jwtauthenticationfilter.sample;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jwtauthenticationfilter.sample.domain.Role;
import org.springframework.security.jwtauthenticationfilter.sample.domain.User;
import org.springframework.security.jwtauthenticationfilter.sample.repository.UserRepository;

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
                addUser("admin", "pwd", Arrays.asList(Role.ADMIN, Role.USER));
                addUser("user", "pwd", Arrays.asList(Role.USER));
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
