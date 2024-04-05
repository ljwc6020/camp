package com.camp.service;

import com.camp.dto.UserDTO;
import org.springframework.transaction.annotation.Transactional;


@Transactional
public interface UserService {
    static class EmailExistException extends Exception{
    }

    static class EmailNotExistException extends RuntimeException{

        public EmailNotExistException(String message){
            super(message);
        }

    }


    //회원등록하는 기능을 수행하는데 이미 동일한 id를 가진 회원이 존재하면 EmailExistException을 처리한다.
    //EmailEXistException 은 회원 등록시 중복된 Email 가 발생한 경우를 나타내는 예외.
    void join(UserDTO userDTO)throws EmailExistException;

    void modifyUser(UserDTO userDTO);

    String resetPassword(String email)throws EmailNotExistException;


}
