package com.innoq.cookiebasedsessionapp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class RedirectToOriginalUrlAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
  private static final Logger LOG = LoggerFactory.getLogger(RedirectToOriginalUrlAuthenticationSuccessHandler.class);
  private static final String DEFAULT_TARGET_URL = "/";


  public RedirectToOriginalUrlAuthenticationSuccessHandler() {
    super(DEFAULT_TARGET_URL);
    this.setTargetUrlParameter(WebSecurityConfig.TARGET_AFTER_SUCCESSFUL_LOGIN_PARAM);
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    UserInfo userInfo = (UserInfo) authentication.getPrincipal();
    userInfo.setColour(request.getParameter(WebSecurityConfig.COLOUR_PARAM));
    super.onAuthenticationSuccess(request, response, authentication);
  }

  @Override
  protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    var targetUrl = super.determineTargetUrl(request, response, authentication);
    if (UrlUtils.isAbsoluteUrl(targetUrl)) {
      LOG.warn("Absolute target URL {} identified and suppressed", targetUrl);
      return DEFAULT_TARGET_URL;
    }
    return targetUrl;
  }
}
