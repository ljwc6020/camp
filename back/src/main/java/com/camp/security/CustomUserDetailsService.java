package com.camp.security;

import java.util.stream.Collectors;

import com.camp.domain.User;
import com.camp.dto.LoginDTO;
import com.camp.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Service  //시큐리티 실행시 UserDetailsService 을 자동으로 찾아 실행시킨다.
@Log4j2
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService{

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.getWithRoles(username);
        if(user == null){
            throw new UsernameNotFoundException("Not Found");
        }
        LoginDTO loginDTO = new LoginDTO(
                user.getEmail(),
                user.getPw(),
                user.getNickname(),
                user.getPhone(),
                user.getBirth(),
                user.getUserRoleList()
                        .stream()
                        .map(userRole -> userRole.name()).collect(Collectors.toList()));

        log.info(loginDTO);
        return loginDTO;
    }

}