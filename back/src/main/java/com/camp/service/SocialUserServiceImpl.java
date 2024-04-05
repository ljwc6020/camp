package com.camp.service;

import java.util.LinkedHashMap;
import java.util.Optional;

import com.camp.domain.User;
import com.camp.domain.UserRole;
import com.camp.dto.LoginDTO;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.camp.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Service
@RequiredArgsConstructor
@Log4j2
public class SocialUserServiceImpl implements SocialUserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Override
    public LoginDTO getKakaoUser(String accessToken) {

        String email = getEmailFromKakaoAccessToken(accessToken);

        log.info("email: " + email );

        Optional<User> result = userRepository.findByEmailWithRoles(email);

        // 기존의 회원
        if(result.isPresent()){
            LoginDTO loginDTO = entityToDTO(result.get());

            return loginDTO;
        }

        // 회원이 아니었다면
        // 패스워드는 임의로 생성
        User socialUser = makeSocialUser(email);
        userRepository.save(socialUser);

        LoginDTO loginDTO = entityToDTO(socialUser);

        return loginDTO;
    }


    private String getEmailFromKakaoAccessToken(String accessToken){

        String kakaoGetUserURL = "https://kapi.kakao.com/v2/user/me";

        if(accessToken == null){
            throw new RuntimeException("Access Token is null");
        }
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();

        headers.add("Authorization", "Bearer " + accessToken);
        headers.add("Content-Type","application/x-www-form-urlencoded");
        HttpEntity<String> entity = new HttpEntity<>(headers);

        UriComponents uriBuilder = UriComponentsBuilder.fromHttpUrl(kakaoGetUserURL).build();

        ResponseEntity<LinkedHashMap> response =
                restTemplate.exchange(
                        uriBuilder.toString(),
                        HttpMethod.GET,
                        entity,
                        LinkedHashMap.class);

        log.info(response);

        LinkedHashMap<String, LinkedHashMap> bodyMap = response.getBody();

        log.info("------------------------------");
        log.info(bodyMap);

        LinkedHashMap<String, String> kakaoAccount = bodyMap.get("kakao_account");

        log.info("kakaoAccount: " + kakaoAccount);

        return kakaoAccount.get("email");

    }

    private String makeTempPassword() {
        // 생성된 비밀번호를 저장할 StringBuffer 생성
        StringBuffer buffer = new StringBuffer();

        // 비밀번호의 길이가 10인지 확인하기위한 10번의 루프
        for(int i = 0;  i < 10; i++){
            // 55를 곱한다는 것은 0부터 54까지
            // 65를 더해서 범위를 준다는 것은 A부터 119(z)결과를 char로 캐스팅하여 문자로 변환
            buffer.append(  (char) ( (int)(Math.random()*55) + 65  ));
        }
        // StringBuffer를 String 으로 변환하고 생성된 비밀번호를 반환
        return buffer.toString();
    }

    private User makeSocialUser(String email) {

        String tempPassword = makeTempPassword();

        log.info("tempPassword: " + tempPassword);


        User user = User.builder()
                .email(email)
                .pw(passwordEncoder.encode(tempPassword))
                .build();

        user.addRole(UserRole.USER);

        return user;

    }


}