package org.springframework.security.jwtauthenticationfilter.sample.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.jwtauthenticationfilter.sample.domain.User;
import org.springframework.security.jwtauthenticationfilter.sample.domain.User;
import org.springframework.transaction.annotation.Transactional;

public interface UserRepository extends JpaRepository<User, Long> {

    @Transactional(readOnly = true)
    User findById(Long id);

    @Transactional(readOnly = true)
    User findByUsername(String username);
}
