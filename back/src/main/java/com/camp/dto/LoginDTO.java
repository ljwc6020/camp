package com.camp.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Log4j2
@Getter
@Setter
@ToString
public class LoginDTO extends User  {


    private String email;

    private String pw;

    private String nickname;

    private String phone;

    private String birth;

    private List<String> roleNames = new ArrayList<>();

    public LoginDTO(String email, String pw, String nickname, String phone, String birth, List<String> roleNames) {
        super(email, pw, roleNames.stream().map(str -> new SimpleGrantedAuthority("ROLE_" + str)).collect(Collectors.toList()));
        this.email = email;
        this.pw = pw;
        this.nickname = nickname;
        this.phone = phone;
        this.birth = birth;
        this.roleNames = roleNames;
    }

    //JWT문자열 생성시에 사용(현재 사용자 정보를 Map 타입으로 반환)
    public Map<String, Object> getClaims() {

        Map<String, Object> dataMap = new HashMap<>();

        dataMap.put("email", email);
        dataMap.put("pw", pw);
        dataMap.put("nickname", nickname);
        dataMap.put("phone", phone);
        dataMap.put("birth", birth);
        dataMap.put("roleNames", roleNames);

        return dataMap;
    }
}
