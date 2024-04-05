package com.camp.service;

import com.camp.domain.User;
import com.camp.domain.UserRole;
import com.camp.dto.UserDTO;
import com.camp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Optional;

@Log4j2
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final ModelMapper modelMapper;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Override
    public void join(UserDTO userDTO) throws EmailExistException {

        String email = userDTO.getEmail();

        boolean exist = userRepository.existsById(email);

        if (exist) {
            throw new EmailExistException();
        }

        User user = modelMapper.map(userDTO, User.class);
        user.changePassword(passwordEncoder.encode(userDTO.getPw()));
        user.addRole(UserRole.ADMIN);

        log.info("============================");
        log.info(user);
        log.info(user.getUserRoleList());

        userRepository.save(user);
    }


    @Override
    public void modifyUser(UserDTO userDTO) {

        Optional<User> result = userRepository.findById(userDTO.getEmail());

        User user = result.orElseThrow();

        user.changePassword(passwordEncoder.encode(userDTO.getPw()));
        user.changeNickname(userDTO.getNickname());
        user.changePhone(userDTO.getPhone());
        user.changeBirth(userDTO.getBirth());

        userRepository.save(user);
    }

    @Override
    public String resetPassword(String email){
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (!userOptional.isPresent()) {
              throw new EmailNotExistException("등록된 이메일이 없습니다. 다시 확인하세요.");
           }

           User user = userOptional.get();
           // 임시 비밀번호 생성 로직
           String tempPassword = generateTempPassword();
           // 비밀번호 인코딩
           String encodedPassword = passwordEncoder.encode(tempPassword);
           // 임시 비밀번호를 사용자 계정에 저장
           user.changePassword(encodedPassword);
           userRepository.save(user);
           // 사용자 이메일로 임시 비밀번호를 포함한 이메일 발송
           emailService.sendEmail(user.getEmail(),
                   "임시비밀번호 발송드립니다.",
                   "회원님의 임시비밀번호: " + tempPassword +"\n보안을 위해 로그인 후 비밀번호 재설정 부탁드립니다.");

           return "비밀번호 재설정 이메일이 발송되었습니다. 등록된 이메일을 확인해 주세요.";
       }


      private String generateTempPassword() {
      // 임시 비밀번호 생성 로직 구현
       String lowerAlphabets = "abcdefghijklmnopqrstuvwxyz";
       String numbers = "0123456789";
       String combinedChars = lowerAlphabets + numbers;
       SecureRandom random = new SecureRandom();
       StringBuilder sb = new StringBuilder(8);

        for (int i = 0; i < 8; i++) {
             sb.append(combinedChars.charAt(random.nextInt(combinedChars.length())));
           }

            return sb.toString();
        }
}