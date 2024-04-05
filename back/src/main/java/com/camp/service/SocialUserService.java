package com.camp.service;

import java.util.stream.Collectors;

import com.camp.domain.User;
import com.camp.dto.LoginDTO;
import org.springframework.transaction.annotation.Transactional;


@Transactional
public interface SocialUserService {

    LoginDTO getKakaoUser(String accessToken);



    default LoginDTO entityToDTO(User user){

        LoginDTO dto = new LoginDTO(
                user.getEmail(),
                user.getPw(),
                user.getNickname(),
                user.getPhone(),
                user.getBirth(),
                user.getUserRoleList().stream().map(userRole -> userRole.name()).collect(Collectors.toList()));
        return dto;
    }
}