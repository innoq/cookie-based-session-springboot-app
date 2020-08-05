# Cookie-based Session Spring-Boot App

This project contains a very simple spring-boot application that stores its user session 
information (e.g. username, roles) in a cookie instead of persisting it on the server-side. 

## Usage

Just as any other spring-boot app it can be started as follows

    mvn spring-boot:run
    
It listens on port 8080 and provides the following pages

* `/` - home page, requires authentication
* `/other` - other page, requires authentication
* `/login` - login form

It uses an in-memory authentication manager which knows exactly one set of valid credentials: 
`bob` / `builder`

## Test

1. open `http://localhost:8080/other`
    * forwarded to `http://localhost:8080/login?target=/other` (login form)
    * hidden input field `target` contains originally requested URL
2. login with credentials
    * forwarded to `http://localhost:8080/other` (other page)
    * `UserInfo` cookie was set, value: `uid=bob&roles=TESTER|USER&hmac=...`
3. open `http://localhost:8080/`
    * home page is displayed (authentication still valid)
4. logout
    * forward to login form
    * hidden input field `target` is empty (no URL requested)
    * `UserInfo` cookie was deleted

## Solution (brief summary)

Details can be found in the code. The `WebSecurityConfig` class is a good entry point. 
 
A more detailed description can be found in a according [blog post][].

### `SessionCreationPolicy.STATELESS`

See https://docs.spring.io/spring-security/site/docs/5.3.3.RELEASE/api/org/springframework/security/config/http/SessionCreationPolicy.html#STATELESS

Prevents the creation of the server-side session. CSRF is strongly coupled with the 
server-side session so it has to be disabled as well to really activate the policy
(see https://github.com/spring-projects/spring-security/issues/5299).  

```java
  protected void configure(HttpSecurity http) throws Exception {
    http
      ...

      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      .and().csrf().disable()

      ...
  }
```

### `CookieSecurityContextRepository`

Replaces the default `HttpSessionSecurityContextRepository` and persists the `SecurityContext` 
in a `Cookie`. 

```java
  protected void configure(HttpSecurity http) throws Exception {
    http
      ...

      .securityContext().securityContextRepository(cookieSecurityContextRepository)
      .and().logout().permitAll().deleteCookies(UserInfoCookie.NAME)

      ...
  }
``` 

### `LoginWithTargetUrlAuthenticationEntryPoint` und `RedirectToOriginalUrlAuthenticationSuccessHandler`

The default `RequestCache` is deactivated and instead the `LoginWithTargetUrlAuthenticationEntryPoint` is used to add 
the originally requested URL to the login form request.

The `RedirectToOriginalUrlAuthenticationSuccessHandler` is used to forward the user to the originally requested URL after 
a successful login.

```java
  protected void configure(HttpSecurity http) throws Exception {
    http
      ...

      .and().requestCache().disable()
      .exceptionHandling().authenticationEntryPoint(loginWithTargetUrlAuthenticationEntryPoint)

      .and().formLogin()
      .loginPage(LOGIN_FORM_URL)
      .successHandler(redirectToOriginalUrlAuthenticationSuccessHandler)

      ...
  }
```

--- 

[blog post]: https://innoq.com/en/blog/cookie-based-spring-security-session/
