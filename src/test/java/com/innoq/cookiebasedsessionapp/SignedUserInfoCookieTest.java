package com.innoq.cookiebasedsessionapp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.servlet.http.Cookie;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SignedUserInfoCookieTest {

  private static final String COOKIE_VALUE_WITH_HMAC = "uid=ab1234&roles=USER|TESTER&colour=YELLOW&hmac=0k9BetqMZOijyq5gaM+2+sqCgDJOpSwHEgkyYwpfIyb5Zcnrsk/BqCWciGBEaYeGWTkMB1CEFJU0So0u8OTUUw==";
  public static final String COOKIE_VALUE_WITHOUT_ROLES = "uid=ab1234&roles=&colour=YELLOW&hmac=w51eeYpz+/lbAOA7KUZC43UeF0nUZZxcKpJFRrh7CyhsR+EE77AaRSJKsq0HxNgbxmuLxsstkV/JiFawwnv47g==";
  public static final String COOKIE_VALUE_WITHOUT_COLOUR = "uid=ab1234&roles=USER|TESTER&hmac=wRYQmJZQ3JLnOiuYLV6ETG0kmz0H+7leJvvl1m14Pb5LP/FupJHdrIhzKc1gApenSNSCSvE20y9+oxwRfvYy8g==";
  private static final String COOKIE_VALUE_WITHOUT_ROLES_AND_COLOUR = "uid=ab1234&roles=&hmac=Tpe2mlTIn0ZzHWnXVtrmDrcEdoLHzOwoeTRyMCpmJkDsawRjfyWgMR6Xc0Qwv79XNoN3o3/QWPcDQwZiK6KY9w==";
  private static final String COOKIE_VALUE_WITHOUT_HMAC = "uid=ab1234&roles=USER|TESTER&colour=YELLOW";
  private static final String COOKIE_VALUE_WITH_INVALID_HMAC = "uid=ab1234&roles=USER|TESTER&colour=YELLOW&hmac=invalid";

  private static final String USERNAME = "ab1234";
  private static final SimpleGrantedAuthority ROLE1 = new SimpleGrantedAuthority("USER");
  private static final SimpleGrantedAuthority ROLE2 = new SimpleGrantedAuthority("TESTER");
  private static final String COLOUR = "YELLOW";

  private static final String SECRET_KEY = "y.E@EA!FbtCwXYB-2v_n.!*xgzRqgtbq2d2_A_U!W2hubL@URHRzNP96WNPxEcXK";
  private static final String HMAC = "0k9BetqMZOijyq5gaM+2+sqCgDJOpSwHEgkyYwpfIyb5Zcnrsk/BqCWciGBEaYeGWTkMB1CEFJU0So0u8OTUUw==";

  @Mock
  private UserInfo userInfo;
  @Mock
  private Cookie cookie;

  @BeforeEach
  public void setupUserInfo() {
    lenient().when(userInfo.getUsername()).thenReturn(USERNAME);
    lenient().when(userInfo.getAuthorities()).thenReturn(List.of(ROLE1, ROLE2));
    lenient().when(userInfo.getColour()).thenReturn(Optional.of(COLOUR));
  }

  @BeforeEach
  public void setupCookie() {
    lenient().when(cookie.getName()).thenReturn(SignedUserInfoCookie.NAME);
    lenient().when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITH_HMAC);
  }

  @Test
  public void create_fromUserInfo() {
    SignedUserInfoCookie signedUserInfoCookie = new SignedUserInfoCookie(userInfo, SECRET_KEY);

    assertThat(signedUserInfoCookie.getValue()).isEqualTo(COOKIE_VALUE_WITH_HMAC);
  }

  @Test
  public void create_fromUserInfo_withoutRoles() {
    when(userInfo.getAuthorities()).thenReturn(List.of());

    SignedUserInfoCookie signedUserInfoCookie = new SignedUserInfoCookie(userInfo, SECRET_KEY);

    assertThat(signedUserInfoCookie.getValue()).isEqualTo(COOKIE_VALUE_WITHOUT_ROLES);
  }

  @Test
  public void create_fromUserInfo_withoutColour() {
    when(userInfo.getColour()).thenReturn(Optional.empty());

    SignedUserInfoCookie signedUserInfoCookie = new SignedUserInfoCookie(userInfo, SECRET_KEY);

    assertThat(signedUserInfoCookie.getValue()).isEqualTo(COOKIE_VALUE_WITHOUT_COLOUR);
  }

  @Test
  public void create_fromBenutzer_ohneRollenLandUndMarke() {
    when(userInfo.getAuthorities()).thenReturn(List.of());
    when(userInfo.getColour()).thenReturn(Optional.empty());

    SignedUserInfoCookie signedUserInfoCookie = new SignedUserInfoCookie(userInfo, SECRET_KEY);

    assertThat(signedUserInfoCookie.getValue()).isEqualTo(COOKIE_VALUE_WITHOUT_ROLES_AND_COLOUR);
  }

  @Test
  public void create_fromCookie() {
    SignedUserInfoCookie signedUserInfoCookie = new SignedUserInfoCookie(cookie, SECRET_KEY);

    assertThat(signedUserInfoCookie.getUsername()).isEqualTo(USERNAME);
    assertThat(signedUserInfoCookie.getRoles()).containsExactlyInAnyOrder(ROLE1.getAuthority(), ROLE2.getAuthority());
    assertThat(signedUserInfoCookie.getColour()).isEqualTo(COLOUR);
    assertThat(signedUserInfoCookie.getHmac()).isEqualTo(HMAC);
  }

  @Test
  public void getUserInfo_fromCookie() {
    UserInfo userInfo = new SignedUserInfoCookie(cookie, SECRET_KEY).getUserInfo();

    assertThat(userInfo.getUsername()).isEqualTo(USERNAME);
    assertThat(userInfo.getAuthorities()).describedAs("roles").containsExactlyInAnyOrder(ROLE1, ROLE2);
    assertThat(userInfo.getColour()).isPresent().hasValue(COLOUR);
  }

  @Test
  public void getUserInfo_fromCookie_withoutRoles() {
    when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITHOUT_ROLES);

    UserInfo userInfo = new SignedUserInfoCookie(cookie, SECRET_KEY).getUserInfo();

    assertThat(userInfo.getAuthorities()).isEmpty();
  }

  @Test
  public void getUserInfo_fromCookie_withoutColour() {
    when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITHOUT_COLOUR);

    UserInfo userInfo = new SignedUserInfoCookie(cookie, SECRET_KEY).getUserInfo();

    assertThat(userInfo.getColour()).isEmpty();
  }

  @Test
  public void getUserInfo_fromCookie_withoutRolesAndColour() {
    when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITHOUT_ROLES_AND_COLOUR);

    UserInfo userInfo = new SignedUserInfoCookie(cookie, SECRET_KEY).getUserInfo();

    assertThat(userInfo.getAuthorities()).isEmpty();
    assertThat(userInfo.getColour()).isEmpty();
  }

  @Test
  public void getUserInfo_fromCookie_missingSignature() {
    when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITHOUT_HMAC);

    assertThatThrownBy(() -> new SignedUserInfoCookie(cookie, SECRET_KEY))
      .isInstanceOf(CookieVerificationFailedException.class);
  }

  @Test
  public void getUserInfo_fromCookie_invalidSignature() {
    when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITH_INVALID_HMAC);

    assertThatThrownBy(() -> new SignedUserInfoCookie(cookie, SECRET_KEY))
      .isInstanceOf(CookieVerificationFailedException.class);
  }

}
