package com.innoq.cookiebasedsessionapp;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

public class UserInfoCookie extends Cookie {

  public static final String NAME = "UserInfo";
  private static final String PATH = "/";
  private static final Pattern UID_PATTERN = Pattern.compile("uid=([A-Za-z0-9]*)");
  private static final Pattern ROLES_PATTERN = Pattern.compile("roles=([A-Z0-9_|]*)");
  private static final Pattern COLOUR_PATTERN = Pattern.compile("colour=([A-Z]*)");
  private static final Pattern HMAC_PATTERN = Pattern.compile("hmac=([A-Za-z0-9+/=]*)");
  private static final String HMAC_SHA_512 = "HmacSHA512";

  private final String username;
  private final List<String> roles;
  private final String colour;
  private String hmac;

  public UserInfoCookie(UserInfo userInfo) {
    super(NAME, "");
    this.username = userInfo.getUsername();
    this.roles = userInfo.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(toList());
    this.colour = userInfo.getColour().orElse(null);
    this.hmac = null; // will be set by the {@link #signWith(String)} method
    this.setPath(PATH);
    this.setMaxAge((int) Duration.of(1, ChronoUnit.HOURS).toSeconds());
    this.setHttpOnly(true);
  }

  public static UserInfoCookie fromCookie(Cookie cookie) {
    if (!NAME.equals(cookie.getName())) {
      throw new IllegalArgumentException("No " + NAME + " Cookie");
    }
    return new UserInfoCookie(cookie);
  }

  private UserInfoCookie(Cookie cookie) {
    super(NAME, "");
    this.username = parse(cookie.getValue(), UID_PATTERN).orElseThrow(() -> new IllegalArgumentException(NAME + " Cookie contains no UID"));
    this.roles = parse(cookie.getValue(), ROLES_PATTERN).map(s -> List.of(s.split("\\|"))).orElse(List.of());
    this.colour = parse(cookie.getValue(), COLOUR_PATTERN).orElse(null);
    this.hmac = parse(cookie.getValue(), HMAC_PATTERN).orElse(null);
    this.setPath(cookie.getPath());
    this.setMaxAge(cookie.getMaxAge());
    this.setHttpOnly(cookie.isHttpOnly());
  }

  private Optional<String> parse(String value, Pattern pattern) {
    Matcher matcher = pattern.matcher(value);
    if (!matcher.find())
      return Optional.empty();

    if (matcher.groupCount() < 1)
      return Optional.empty();

    String match = matcher.group(1);
    if (match == null || match.trim().isEmpty())
      return Optional.empty();

    return Optional.of(match);
  }

  @Override
  public String getValue() {
    return getPayload() + appendHmac();
  }

  private String getPayload() {
    return "uid=" + username +
      "&roles=" + String.join("|", roles) +
      (colour != null ? "&colour=" + colour : "");
  }

  private String appendHmac() {
    if (hmac == null)
      return "";
    return "&hmac=" + hmac;
  }

  public UserInfo getUserInfo() {
    var userInfo = new UserInfo(username, roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
    userInfo.setColour(colour);
    return userInfo;
  }

  public void signWith(String secretKey) {
    this.hmac = calculateHmac(getPayload(), secretKey);
  }

  public void verifyWith(String secretKey) {
    if (this.hmac == null)
      throw new CookieVerificationFailedException("Cookie not signed (no HMAC)");
    if (!this.hmac.equals(calculateHmac(getPayload(), secretKey)))
      throw new CookieVerificationFailedException("Cookie signature (HMAC) invalid");
  }

  private String calculateHmac(String value, String secretKey) {
    byte[] secretKeyBytes = Objects.requireNonNull(secretKey).getBytes(StandardCharsets.UTF_8);
    byte[] valueBytes = Objects.requireNonNull(value).getBytes(StandardCharsets.UTF_8);

    try {
      Mac mac = Mac.getInstance(HMAC_SHA_512);
      SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, HMAC_SHA_512);
      mac.init(secretKeySpec);
      byte[] hmacBytes = mac.doFinal(valueBytes);
      return Base64.getEncoder().encodeToString(hmacBytes);

    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Only for testing.
   */
  String getUsername() {
    return username;
  }

  /**
   * Only for testing.
   */
  List<String> getRoles() {
    return roles;
  }

  /**
   * Only for testing.
   */
  String getColour() {
    return colour;
  }

  /**
   * Only for testing.
   */
  String getHmac() {
    return hmac;
  }

  /**
   * Only for testing.
   */
  void setHmac(String hmac) {
    this.hmac = hmac;
  }
}
