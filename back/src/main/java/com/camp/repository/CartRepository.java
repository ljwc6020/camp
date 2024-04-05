package com.camp.repository;

import java.util.Optional;

import com.camp.domain.Cart;
import com.camp.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface CartRepository extends JpaRepository<Cart, Long>{

    // User의 이메일을 기반으로 해당 User의 Cart를 조회하는 쿼리 메서드
    @Query("select cart from Cart cart where cart.owner.email = :email")
    public Optional<Cart> getCartOfMember(@Param("email") String email);
    @Transactional
    void deleteByOwnerEmail(String ownerEmail);

    @Query("select cart.cno from Cart cart where cart.owner.email = :email")
    Long findCinoByEmail(@Param("email") String email);
}
