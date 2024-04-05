package com.camp.security.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.camp.dto.LoginDTO;
import com.camp.util.JWTUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;

@Log4j2       //OncePerRequestFilter : 모든 요청에 대해서 체크한다.
public class JWTCheckFilter extends OncePerRequestFilter{

    @Override         //shouldNotFilter : 필터로 체크하지 않을 경로나 메서드(get/post)등을 지정할 수 있음.
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        // Preflight요청은 체크하지 않음
        if (request.getMethod().equals("OPTIONS")) {
            return true;    //건너뛰어라
        }

        String path = request.getRequestURI();

        log.info("check uri......................." + path);

        //api/user/ 경로의 호출은 체크하지 않음
        if (path.startsWith("/api/user/")) {
            log.info("get here?????????????????");
            return true;
        }
        if(path.startsWith("/api/products/list")){
            return true;
        }
        if (path.startsWith("/review/view")) {
            log.info("get here?????????????????");
            return true;
        }
        if(path.startsWith("/api/products/view")){
            return true;
        }
        if(path.startsWith("/api/products/read")){
            return true;
        }
        if(path.startsWith("/camp")){
            return true;
        }
        if(path.startsWith("/images")){
            return true;
        }
        if(path.startsWith("/sea")){
            return true;
        }
        if(path.startsWith("/mountain")){
            return true;
        }
        if (path.startsWith("/review/list")) {
            log.info("get here?????????????????");
            return true;
        }
        if (path.startsWith("/review/read")) {
            log.info("get here?????????????????");
            return true;
        }
        if (path.startsWith("/qna/list")) {
            log.info("get here?????????????????");
            return true;
        }
        if (path.startsWith("/qna/read")) {
            log.info("get here?????????????????");
            return true;
        }


    return false;  //위에 것들이 아니면 건너뛰지 말아라
   }


    @Override  //Acces Token에 대한 확인
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
    throws IOException{


        log.info("------------------------JWTCheckFilter------------------");

    String authHeaderStr = request.getHeader("Authorization");

    try {
      //Bearer accestoken...
      String accessToken = authHeaderStr.substring(7);  //Bearer과 스페이스 한칸 뒤부터 시작하기 때문에 7부터 확인한다.
      Map<String, Object> claims = JWTUtil.validateToken(accessToken);

      log.info("JWT claims: " + claims);

        String email = (String) claims.get("email");
        String pw = (String) claims.get("pw");
        String nickname = (String) claims.get("nickname");
        String phone = (String) claims.get("phone");
        String birth = (String) claims.get("birth");
        List<String> roleNames = (List<String>) claims.get("roleNames");

              LoginDTO loginDTO = new LoginDTO(email, pw, nickname, phone, birth, roleNames);

              log.info("-----------------------------------");
              log.info(loginDTO);
              log.info(loginDTO.getAuthorities());

              UsernamePasswordAuthenticationToken authenticationToken
              = new UsernamePasswordAuthenticationToken(loginDTO, pw, loginDTO.getAuthorities());

              SecurityContextHolder.getContext().setAuthentication(authenticationToken);

              filterChain.doFilter(request, response);

            }catch(Exception e){

        String path = request.getRequestURI();
              log.error("JWT Check Error..............");
              log.info(path);
              log.error(e.getMessage());

              Gson gson = new Gson();
              String msg = gson.toJson(Map.of("error", "ERROR_ACCESS_TOKEN"));

              response.setContentType("application/json");
              PrintWriter printWriter = response.getWriter();
              printWriter.println(msg);
              printWriter.close();

            }
          }
        }