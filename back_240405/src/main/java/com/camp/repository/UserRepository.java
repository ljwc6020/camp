package com.camp.repository;

import com.camp.domain.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {


    //로그인시 데이터 가져오기
    @EntityGraph(attributePaths = {"userRoleList"})
    @Query("select u from User u where u.email = :email")
    User getWithRoles(@Param("email") String email);

    //카카오회원가입시 같은 이메일 값 있는지 확인
    @Query("select u from User u where u.email = :email")
    Optional<User> findByEmailWithRoles(@Param("email") String email);

    @EntityGraph(attributePaths = {"userRoleList"})
    Optional<User> findByEmail(String email);

}
