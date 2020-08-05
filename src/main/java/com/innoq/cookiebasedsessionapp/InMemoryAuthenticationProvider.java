package com.innoq.cookiebasedsessionapp;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Set;

@Component
class InMemoryAuthenticationProvider implements AuthenticationProvider {

  private static final Collection<UserInfo> userInfos = Set.of(
    new UserInfo("bob", "builder",
      Set.of(new SimpleGrantedAuthority("USER"), new SimpleGrantedAuthority("TESTER"))));

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    UserInfo userInfo = InMemoryAuthenticationProvider.userInfos.stream()
      .filter(b -> b.getUsername().equals(authentication.getName()))
      .findFirst()
      .orElseThrow(() -> new UsernameNotFoundException(""));
    return new UsernamePasswordAuthenticationToken(userInfo, userInfo.getPassword(), userInfo.getAuthorities());
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
