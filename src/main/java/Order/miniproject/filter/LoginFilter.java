package Order.miniproject.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.PatternMatchUtils;
import org.springframework.web.util.pattern.PathPattern;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.UUID;

@Slf4j
public class LoginFilter implements Filter {

  private static final String[] whiteLists = {"/",
      "/home", "/members/login","/members/addMember",
      "/members/logout","/css/*"};
  // 로그 필터와 달리 '/*'
  // 로그인 필터는 적용을 할 URI와 적용하지 않을 URI가 다르다
  //  /items/*, /orders/*

  // 적용하지 않을 URI -- /, /members/login, /members/addMember,
  // /members/logout, /css/*

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;
    String requestURI = httpRequest.getRequestURI();
    String uuid = UUID.randomUUID().toString();

    log.info("로그인 인증 필터 시작 : [{}], [{}]",uuid,requestURI);
    //whitelists 앉에 있는 uri로 접근하는 경우에는 로그인 체크를 하지않음
    //whitelists를 제외한 uri로 접근하는 경우에만 로그인 체크를 함
    try {
      if(PatternMatchUtils.simpleMatch(whiteLists, requestURI)){
        chain.doFilter(request, response);
      }else{
        HttpSession session = httpRequest.getSession(false);
        if(session == null || session.getAttribute("loginMember") == null){
          httpResponse.sendRedirect("/members/login?redirectURL="+requestURI);
          return; // 미인증사용자를 login 하도록 내보내면서 요청 url 정보를 함께 넘겨줌
        }
      }
    } catch (Exception e) {
      throw e;
    } finally {
      log.info("로그인 인증 필터 종료 : [{}], [{}]",uuid,requestURI);
    }
  }
}
