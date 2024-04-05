package com.camp.controller;

import java.security.Principal;
import java.util.List;

import com.camp.domain.Cart;
import com.camp.dto.CartItemDTO;
import com.camp.dto.CartItemListDTO;
import com.camp.service.CartService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Log4j2
@RequestMapping("/api/cart")
public class CartController {

    private final CartService cartService;

    // 카트 아이템 수량 변경 요청을 처리하는 메서드
    @PreAuthorize("#itemDTO.email == authentication.name")
    @PostMapping("/change")
    public List<CartItemListDTO> changeCart(@RequestBody CartItemDTO itemDTO){
        log.info(itemDTO);
        if(itemDTO.getQty() <= 0) {
            return cartService.remove(itemDTO.getCino());
        }
        return cartService.addOrModify(itemDTO);
    }

    // 로그인한 사용자의 카트 아이템 목록 조회 요청을 처리하는 메서드

    @GetMapping("/items")
    public List<CartItemListDTO> getCartItems(Principal principal){
        String email = principal.getName();
        log.info("-------------------------");
        log.info("email: "+ email);
        return cartService.getCartItems(email);
    }

    // 카트 아이템 삭제 요청을 처리하는 메서드

    @DeleteMapping("/{cino}")
    public List<CartItemListDTO> removeFromCart(@PathVariable("cino") Long cino){
        log.info("cart item no: "+ cino);
        return cartService.remove(cino);
    }



}
