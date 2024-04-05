package com.camp.repository;



import com.camp.domain.User;
import com.camp.domain.UserRole;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.stream.IntStream;


@SpringBootTest
@Log4j2
public class UserRepositoryTests {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void testInsertUser(){

        for (int i = 10; i < 11 ; i++) {

            User user = User.builder()
                    .email("user"+i+"@aaa.com")
                    .pw(passwordEncoder.encode("1111a!"))
                    .build();
//            user.addRole(UserRole.USER);
            user.addRole(UserRole.ADMIN);
//            if(i <= 1){
//                user.addRole(UserRole.ADMIN);
//            }
            userRepository.save(user);
        }
    }

    @Test
    public void testRead() {

        String email = "user3@aaa.com";

        User user = userRepository.getWithRoles(email);

        log.info("-----------------");
        log.info(user);
    }
}
