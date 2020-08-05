package com.innoq.cookiebasedsessionapp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class RedirectToOriginalUrlAuthenticationSuccessHandlerTest {

  @Mock
  private HttpServletRequest request;
  @Mock
  private HttpServletResponse response;
  @Mock
  private Authentication authentication;
  @Mock
  private UserInfo userInfo;

  @InjectMocks
  private RedirectToOriginalUrlAuthenticationSuccessHandler handler;

  @Test
  public void onAuthenticationSuccess_addsColourToUserInfo() throws IOException, ServletException {
    when(authentication.getPrincipal()).thenReturn(userInfo);
    when(request.getParameter("colour")).thenReturn("YELLOW");

    handler.onAuthenticationSuccess(request, response, authentication);

    verify(userInfo).setColour("YELLOW");
  }

  @Test
  public void determineTargetUrl_returnsTargetUrlFromRequest() {
    when(request.getParameter(WebSecurityConfig.TARGET_AFTER_SUCCESSFUL_LOGIN_PARAM)).thenReturn("/target");

    var targetUrl = handler.determineTargetUrl(request, response, authentication);

    assertThat(targetUrl).isEqualTo("/target");
  }

  @Test
  public void determineTargetUrl_suppressAbsolutUrls() {
    when(request.getParameter(WebSecurityConfig.TARGET_AFTER_SUCCESSFUL_LOGIN_PARAM)).thenReturn("http://www.google.de");

    var targetUrl = handler.determineTargetUrl(request, response, authentication);

    assertThat(targetUrl).isEqualTo("/");
  }

}
