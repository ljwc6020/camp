package com.camp.domain;

import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Setter
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = "userRoleList")
public class User {

    @Id
    private String email;

    private String pw;

    private String nickname;

    private String phone;

    private String birth;

    @ElementCollection(fetch = FetchType.LAZY)  //부모의 엔티티와는 별도로 컬랙션을 관리하고 처리하는걸 도와줌
    @Builder.Default
    private List<UserRole> userRoleList = new ArrayList<>();

    public void addRole(UserRole userRole){userRoleList.add(userRole);}

    public void changePassword(String pw){
        this.pw = pw;
    }

    public void changeNickname(String nickname){this.nickname = nickname;}


    public void changePhone(String phone) {this.phone =phone;}

    public void changeBirth(String birth) {this.birth = birth;}


}