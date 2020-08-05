package com.innoq.cookiebasedsessionapp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CookieSecurityContextRepositoryTest {

  private static final String COOKIE_VALUE = "uid=ab1234&roles=USER|TESTER&colour=YELLOW&hmac=0k9BetqMZOijyq5gaM+2+sqCgDJOpSwHEgkyYwpfIyb5Zcnrsk/BqCWciGBEaYeGWTkMB1CEFJU0So0u8OTUUw==";
  private static final String COOKIE_VALUE_WITHOUT_HMAC = "uid=ab1234&roles=USER|TESTER&colour=YELLOW";
  private static final String COOKIE_VALUE_WITH_INVALID_HMAC = "uid=ab1234&roles=USER|TESTER&colour=YELLOW&hmac=invalid";

  private static final String USERNAME = "ab1234";
  private static final SimpleGrantedAuthority ROLE1 = new SimpleGrantedAuthority("USER");
  private static final SimpleGrantedAuthority ROLE2 = new SimpleGrantedAuthority("TESTER");
  private static final String COLOUR = "YELLOW";

  private static final String COOKIE_HMAC_KEY = "y.E@EA!FbtCwXYB-2v_n.!*xgzRqgtbq2d2_A_U!W2hubL@URHRzNP96WNPxEcXK";


  @Mock
  private HttpServletRequest request;
  @Mock
  private HttpServletResponse response;
  @Mock
  private Cookie userInfoCookie;

  @Mock
  private SecurityContext securityContext;
  @Mock
  private UsernamePasswordAuthenticationToken usernamePasswordAuthentication;
  @Mock
  private UserInfo userInfo;

  @Captor
  private ArgumentCaptor<Cookie> cookieCaptor;

  private HttpRequestResponseHolder requestResponseHolder;

  private final CookieSecurityContextRepository securityContextRepository = new CookieSecurityContextRepository(COOKIE_HMAC_KEY);

  @BeforeEach
  public void setupRequestResponseHolder() {
    requestResponseHolder = new HttpRequestResponseHolder(request, response);
  }

  @BeforeEach
  public void setupUserInfoCookie() {
    lenient().when(userInfoCookie.getName()).thenReturn(UserInfoCookie.NAME);
    lenient().when(userInfoCookie.getValue()).thenReturn(COOKIE_VALUE);
  }

  @BeforeEach
  public void setupSecurityContext() {
    lenient().when(securityContext.getAuthentication()).thenReturn(usernamePasswordAuthentication);
    lenient().when(usernamePasswordAuthentication.getPrincipal()).thenReturn(userInfo);
    lenient().when(userInfo.getUsername()).thenReturn(USERNAME);
    lenient().when(userInfo.getAuthorities()).thenReturn(List.of(ROLE1, ROLE2));
    lenient().when(userInfo.getColour()).thenReturn(Optional.of(COLOUR));
  }

  @Test
  public void loadContext_noCookieInRequest() {
    SecurityContext securityContext = securityContextRepository.loadContext(requestResponseHolder);

    assertThat(securityContext).isNotNull();
    assertThat(securityContext.getAuthentication()).isNull();
  }

  @Test
  public void loadContext_cookieCompletelyFilled() {
    when(request.getCookies()).thenReturn(new Cookie[]{userInfoCookie});
    SecurityContext securityContext = securityContextRepository.loadContext(requestResponseHolder);

    assertThat(securityContext).isNotNull();
    assertThat(securityContext.getAuthentication()).isNotNull();
    assertThat(securityContext.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);

    UsernamePasswordAuthenticationToken usernamePasswordToken = (UsernamePasswordAuthenticationToken) securityContext.getAuthentication();
    assertThat(usernamePasswordToken.isAuthenticated()).isTrue();
    assertThat(usernamePasswordToken.getPrincipal()).isInstanceOf(UserInfo.class);

    UserInfo userInfo = (UserInfo) usernamePasswordToken.getPrincipal();
    assertThat(userInfo.getUsername()).isEqualTo(USERNAME);
  }

  @Test
  public void loadContext_cookieWithoutHmac() {
    when(userInfoCookie.getValue()).thenReturn(COOKIE_VALUE_WITHOUT_HMAC);
    when(request.getCookies()).thenReturn(new Cookie[]{userInfoCookie});

    assertThatThrownBy(() -> securityContextRepository.loadContext(requestResponseHolder))
      .isInstanceOf(CookieVerificationFailedException.class);
  }

  @Test
  public void loadContext_cookieWithInvalidHmac() {
    when(userInfoCookie.getValue()).thenReturn(COOKIE_VALUE_WITH_INVALID_HMAC);
    when(request.getCookies()).thenReturn(new Cookie[]{userInfoCookie});

    assertThatThrownBy(() -> securityContextRepository.loadContext(requestResponseHolder))
      .isInstanceOf(CookieVerificationFailedException.class);
  }

  @Test
  public void containsContext_noCookieInRequest_returnsFalse() {
    assertThat(securityContextRepository.containsContext(request)).isFalse();
  }

  @Test
  public void containsContext_cookieInRequest_returnsTrue() {
    when(request.getCookies()).thenReturn(new Cookie[]{userInfoCookie});
    assertThat(securityContextRepository.containsContext(request)).isTrue();
  }

  @Test
  public void saveContext_completelyFilledUserInfo() {
    // loadContext is called first to replace (plain) response with internal wrapper
    securityContextRepository.loadContext(requestResponseHolder);

    securityContextRepository.saveContext(securityContext, requestResponseHolder.getRequest(), requestResponseHolder.getResponse());

    verify(response).addCookie(cookieCaptor.capture());
    Cookie cookie = cookieCaptor.getValue();
    assertThat(cookie.getName()).isEqualTo(UserInfoCookie.NAME);
    assertThat(cookie.getValue()).isEqualTo(COOKIE_VALUE);
  }

}
