package org.springframework.security.jwt.sample.customfilter.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.jwt.sample.customfilter.domain.User;
import org.springframework.transaction.annotation.Transactional;

public interface UserRepository extends JpaRepository<User, Long> {

    @Transactional(readOnly = true)
    User findById(Long id);

    @Transactional(readOnly = true)
    User findByUsername(String username);
}
