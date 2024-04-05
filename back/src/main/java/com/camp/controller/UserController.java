package com.camp.controller;

import com.camp.domain.User;
import com.camp.dto.LoginDTO;
import com.camp.dto.UserDTO;
import com.camp.repository.CartItemRepository;
import com.camp.repository.CartRepository;
import com.camp.repository.UserRepository;
import com.camp.service.SocialUserService;
import com.camp.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.*;

import com.camp.util.JWTUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;


@RequestMapping("/api/user")
@RestController
@Log4j2
@RequiredArgsConstructor
public class UserController {

    private final SocialUserService socialUserService;

    private final UserService userService;

    private final UserRepository userRepository;

    private final JavaMailSender javaMailSender;

    private final CartRepository cartRepository;

    private final CartItemRepository cartItemRepository;

    @GetMapping("/kakao")
    public Map<String, Object> getUserFromKakao(String accessToken) {

        log.info("accessToken ");
        log.info(accessToken);

        LoginDTO loginDTO = socialUserService.getKakaoUser(accessToken);

        Map<String, Object> claims = loginDTO.getClaims();  //카카오로 처리된 회원의 정보

        String jwtAccessToken = JWTUtil.generateToken(claims, 10);  //JWT형태로 생성해서 넣어주는 것
        String jwtRefreshToken = JWTUtil.generateToken(claims, 60*1);

        claims.put("accessToken", jwtAccessToken);  //정보 넣기
        claims.put("refreshToken", jwtRefreshToken);

        return claims;
    }


    @PostMapping("/join")
    public ResponseEntity<Map<String, String>> joinPOST(@RequestBody UserDTO userDTO) {
        try {
            userService.join(userDTO);
            return ResponseEntity.ok().body(Map.of("status", "success"));
        } catch (UserService.EmailExistException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("status", "already_exists"));
        }
    }


    @GetMapping("/mypage/{email}")
    public ResponseEntity<?> userGet(@PathVariable  String email) {

        log.info("now user is : " + email);

        // 이메일을 사용하여 UserRepository로부터 사용자 정보 조회
        Optional<User> user = userRepository.findByEmail(email);
        return ResponseEntity.ok(user); // 조회된 사용자 정보 반환
    }



    //수정
    @PutMapping("/modify")
    public Map<String,String> modifyUser(@RequestBody UserDTO userDTO) {

        log.info("member modify: " + userDTO);

        userService.modifyUser(userDTO);

        return Map.of("result","modified");
    }

    @DeleteMapping("/remove/{email}")
    public ResponseEntity<?> removeUser(@PathVariable String email) {
        log.info("bye~ " + email);
        // email 로 장바구니 안에 아이템을 체크
        Long cino = cartRepository.findCinoByEmail(email);

        // 장바구니 체크
        if (cino != null) {
            // 카트가 존재하는 경우에만 카트 아이템 삭제
            cartItemRepository.deleteAllById(Collections.singleton(cino));
            // 카트 삭제
            cartRepository.deleteByOwnerEmail(email);
            // 만약 사용자가 장바구니에 아무 아이템도 담지 않았다면, cart가 생성되지 않습니다. 그래서 체크가 필요합니다
        }

        Optional<User> user = userRepository.findByEmail(email);
        if (user.isPresent()) {
            // 사용자 삭제
            userRepository.delete(user.get());
            return ResponseEntity.ok().body("회원 탈퇴가 성공적으로 처리되었습니다.");
        } else {
            // 사용자를 찾을 수 없음
            return ResponseEntity.notFound().build();
        }
    }


    @PostMapping("/reset-pw")
       public ResponseEntity<String> resetPassword(@RequestParam("email") String email) {
        try {
                   String message = userService.resetPassword(email);
                   return ResponseEntity.ok(message);
               } catch (UserService.EmailNotExistException ex) {
                   return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
               }
           }
}