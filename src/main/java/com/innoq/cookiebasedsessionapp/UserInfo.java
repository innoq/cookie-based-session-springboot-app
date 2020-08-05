package com.innoq.cookiebasedsessionapp;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;

public class UserInfo implements UserDetails {

  private static final String EMPTY_PASSWORD = "";

  private final String username;
  private final String password;
  private final Set<GrantedAuthority> authorities;

  private String colour;

  UserInfo(String username, Set<GrantedAuthority> authorities) {
    this(username, "", authorities);
  }

  UserInfo(String username, String password, Set<GrantedAuthority> authorities) {
    this.username = username;
    this.password = password;
    this.authorities = authorities;
  }

  @Override
  public Collection<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public String getPassword() {
    return EMPTY_PASSWORD;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

  public Optional<String> getColour() {
    return Optional.ofNullable(colour);
  }

  public void setColour(String colour) {
    if (colour == null || colour.isBlank())
      this.colour = null;
    else
      this.colour = colour;
  }
}
