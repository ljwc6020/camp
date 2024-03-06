package com.camp.config;


import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@RequiredArgsConstructor
@Log4j2
@Configuration        //스프링 시큐리의 설정을 코드로 작성
@EnableMethodSecurity   //어노테이션으로 권한을 설정할 수 있다.
public class UserSecurityConfig {

    private final DataSource dataSource;  //쿠키와 관련된 정보를 테이블로 보관하도록 지정
    private final UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        log.info("----------configure-----------");
        //로그인페이지 및 로그인 처리를 자동으로 설정해줌.
        //사용자 지정 로그인 페이지 및 로직을 구현하지 않아도 됨.
//        http.formLogin(Customizer.withDefaults());

        http.formLogin(config->{
            config.loginPage("/member/login");

        });

        //csrf 비활성화
        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());
        http.logout(httpSecurityLogoutConfigurer -> httpSecurityLogoutConfigurer.logoutUrl("/logout"));

        http.rememberMe(config->{
            config.key("12345678")
                    .tokenRepository(persistentTokenRepository())
                    .userDetailsService(userDetailsService)
                    .tokenValiditySeconds(60*60*24*30)  //한달유효
                    .alwaysRemember(true);  // 항상 Remember-Me 기능 사용
        });

        http.oauth2Login(config -> {
            config.loginPage("/member/login");
        });

        return http.build();   //httpSecurity 모두
    }

    @Bean      //정적 파일(css, js 등은 시큐리티 적용할 필요가 없기에 제외)
    public WebSecurityCustomizer webSecurityCustomizer(){
        log.info("------------------web configure------------------");

        return web -> web.ignoring().
                requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean      //remember-me 쿠키를 생성할 때 쿠키의 값을 인코딩하기 위한 키(key) 값과 필요한 정보를 저장하는 TokenRepository가 필요.
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
        repo.setDataSource(dataSource);
        return repo;
    }
}