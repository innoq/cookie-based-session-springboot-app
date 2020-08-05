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
public class UserInfoCookieTest {

  private static final String COOKIE_VALUE_WITH_HMAC = "uid=ab1234&roles=USER|TESTER&colour=YELLOW&hmac=0k9BetqMZOijyq5gaM+2+sqCgDJOpSwHEgkyYwpfIyb5Zcnrsk/BqCWciGBEaYeGWTkMB1CEFJU0So0u8OTUUw==";
  private static final String COOKIE_VALUE_WITHOUT_HMAC = "uid=ab1234&roles=USER|TESTER&colour=YELLOW";
  public static final String COOKIE_VALUE_WITHOUT_ROLES = "uid=ab1234&roles=&colour=YELLOW";
  public static final String COOKIE_VALUE_WITHOUT_COLOUR = "uid=ab1234&roles=USER|TESTER";
  private static final String COOKIE_VALUE_WITHOUT_ROLES_AND_COLOUR = "uid=ab1234&roles=";

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
    lenient().when(cookie.getName()).thenReturn(UserInfoCookie.NAME);
    lenient().when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITH_HMAC);
  }

  @Test
  public void create_fromUserInfo() {
    UserInfoCookie userInfoCookie = new UserInfoCookie(userInfo);

    assertThat(userInfoCookie.getValue()).isEqualTo(COOKIE_VALUE_WITHOUT_HMAC);
  }

  @Test
  public void create_fromUserInfo_withoutRoles() {
    when(userInfo.getAuthorities()).thenReturn(List.of());

    UserInfoCookie userInfoCookie = new UserInfoCookie(userInfo);

    assertThat(userInfoCookie.getValue()).isEqualTo(COOKIE_VALUE_WITHOUT_ROLES);
  }

  @Test
  public void create_fromUserInfo_withoutColour() {
    when(userInfo.getColour()).thenReturn(Optional.empty());

    UserInfoCookie userInfoCookie = new UserInfoCookie(userInfo);

    assertThat(userInfoCookie.getValue()).isEqualTo(COOKIE_VALUE_WITHOUT_COLOUR);
  }

  @Test
  public void create_fromBenutzer_ohneRollenLandUndMarke() {
    when(userInfo.getAuthorities()).thenReturn(List.of());
    when(userInfo.getColour()).thenReturn(Optional.empty());

    UserInfoCookie userInfoCookie = new UserInfoCookie(userInfo);

    assertThat(userInfoCookie.getValue()).isEqualTo(COOKIE_VALUE_WITHOUT_ROLES_AND_COLOUR);
  }

  @Test
  public void create_fromCookie() {
    UserInfoCookie userInfoCookie = UserInfoCookie.fromCookie(cookie);

    assertThat(userInfoCookie.getUsername()).isEqualTo(USERNAME);
    assertThat(userInfoCookie.getRoles()).containsExactlyInAnyOrder(ROLE1.getAuthority(), ROLE2.getAuthority());
    assertThat(userInfoCookie.getColour()).isEqualTo(COLOUR);
    assertThat(userInfoCookie.getHmac()).isEqualTo(HMAC);
  }

  @Test
  public void getUserInfo_fromCookie() {
    UserInfo userInfo = UserInfoCookie.fromCookie(cookie).getUserInfo();

    assertThat(userInfo.getUsername()).isEqualTo(USERNAME);
    assertThat(userInfo.getAuthorities()).describedAs("roles").containsExactlyInAnyOrder(ROLE1, ROLE2);
    assertThat(userInfo.getColour()).isPresent().hasValue(COLOUR);
  }

  @Test
  public void getUserInfo_fromCookie_withoutRoles() {
    when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITHOUT_ROLES);

    UserInfo userInfo = UserInfoCookie.fromCookie(cookie).getUserInfo();

    assertThat(userInfo.getAuthorities()).isEmpty();
  }

  @Test
  public void getUserInfo_fromCookie_withoutColour() {
    when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITHOUT_COLOUR);

    UserInfo userInfo = UserInfoCookie.fromCookie(cookie).getUserInfo();

    assertThat(userInfo.getColour()).isEmpty();
  }

  @Test
  public void getUserInfo_fromCookie_withoutRolesAndColour() {
    when(cookie.getValue()).thenReturn(COOKIE_VALUE_WITHOUT_ROLES_AND_COLOUR);

    UserInfo userInfo = UserInfoCookie.fromCookie(cookie).getUserInfo();

    assertThat(userInfo.getAuthorities()).isEmpty();
    assertThat(userInfo.getColour()).isEmpty();
  }

  @Test
  public void sign() {
    UserInfoCookie cookie = new UserInfoCookie(userInfo);

    cookie.signWith(SECRET_KEY);

    assertThat(cookie.getValue()).isEqualTo(COOKIE_VALUE_WITH_HMAC);
  }

  @Test
  public void verifySignature() {
    UserInfoCookie cookie = new UserInfoCookie(userInfo);
    cookie.setHmac(HMAC);

    cookie.verifyWith(SECRET_KEY);

    // no exception was thrown = valid
  }

  @Test
  public void verifySignature_failIfMissing() {
    UserInfoCookie cookie = new UserInfoCookie(userInfo);
    cookie.setHmac(null);

    assertThatThrownBy(() -> cookie.verifyWith(SECRET_KEY))
      .isInstanceOf(CookieVerificationFailedException.class);
  }

  @Test
  public void verifySignature_failIfInvalid() {
    UserInfoCookie cookie = new UserInfoCookie(userInfo);
    cookie.setHmac("invalidHmac");

    assertThatThrownBy(() -> cookie.verifyWith(SECRET_KEY))
      .isInstanceOf(CookieVerificationFailedException.class);
  }

}
