# 기본 로그인

### 인터페이스 구현

---



Spring Security 를 이용한 인증에서는 AuthenticationManager 의 authenticate() 메소드를 통해 인증을 진행하게 되는데, 그 과정에서 추상화되어 있는 UserDetails, UserDetailsService 인터페이스를 구현해주어야 합니다.



**UserDetailsImpl**

UserDetails 인터페이스를 구현하는 UserDetailsImpl 클래스는 인증된 유저의 데이터를 담게 되는 클래스입니다.

```java
@Getter
@Setter
@NoArgsConstructor
public class UserDetailsImpl implements UserDetails {

    private Long id;
    private String name;
    private String email;
    private String username;
    private String password;
    private UserType type;
    private Collection<? extends GrantedAuthority> authorities;

    @Builder
    public UserDetailsImpl(Long id, String name, String email, String username, String password, UserType type, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.username = username;
        this.password = password;
        this.type = type;
        this.authorities = authorities;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
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
}
```



#### UserDetailsServiceImpl

UserDetailsServiceImpl 클래스는 로그인시에 파라미터로 전달된 username 값을 이용해 계정 정보를 찾아 넘겨주게 됩니다.

```java
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() ->
                new UsernameNotFoundException("등록되지 않은 회원입니다."));

        UserDetailsImpl userDetails = UserDetailsImpl.builder()
                .id(user.getId())
                .username(user.getUsername())
                .name(user.getName())
                .email(user.getEmail())
                .password(user.getPassword())
                .type(user.getType())
                .authorities(user.getAuthorities())
                .build();

        return userDetails;
    }
}
```



### UserDetailsService 인터페이스 구현체 등록

---



UserDetailsService 인터페이스 구현체와 PasswordEncoder 를 인증 과정에서 사용되도록  AuthenticationManagerBuilder 를 통해 등록해 주고 AuthenticationManager 를 @Bean 으로 등록해줍니다.

그리고 로그인 API를 미인증 상태에서만 호출 할 수 있도록 anonymous() 로 추가합니다.



**SecurityConfigurer**

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {

    private final UserDetailsServiceImpl userDetailsService;

    /*
         AuthenticationManager 에서 authenticate 메소드를 실행할때
         내부적으로 사용할 UserDetailsService 와 PasswordEncoder 를 설정
    */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }
  
  	@Override
    protected void configure(HttpSecurity http) throws Exception {
        http....   
          			.authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .antMatchers(HttpMethod.POST, "/authorize", "/users").anonymous()
                .anyRequest().authenticated().and()
                .exceptionHandling()
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
    }


    /*PasswordEncoder를 BCryptPasswordEncoder로 사용하도록 Bean 등록*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}
```



### Util 클래스

---



**DateConvertor**

LocalDateTime 타입의 데이터와 다른 타입의 데이터 간의 변환이 용이하도록 구현한 클래스입니다.

```java
public class DateConvertor {

    public static Date toDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    public static Long toEpochMilli (LocalDateTime localDateTime) {
        return localDateTime.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }

    public static LocalDateTime toLocalDateTime(Date date) {
        Instant instant = date.toInstant();
        return LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
    }
}
```



**CookieUtils**

웹상의 많은 자료들이 LocalStorage 를 이용해 토큰을 저장하는 방식을 소개하고 있는데 LocalStorage 는 javascript 코드로 접근이 가능하기 때문에 XSS 공격에 취약하다는 단점이 있기 때문에 중요한 데이터를 보관하는 장소로는 사용하지 않는 것을 권장하고 있습니다. 

반면에 쿠키는 httpOnly 옵션을 사용하면 http 통신 상에서만 쿠키가 사용되어 javascript 코드를 통한 접근을 막을 수 있으며, secure 옵션을 사용하면 https 통신에서만 쿠키를 전송하게 되어 보안을 더 강화할 수 있습니다.

물론, 쿠키는 CSRF (Cross Site Request Forgery - 사이트 간 요청 위조) 공격에 노출될 수 있지만 XSS 공격에 비해 완벽한 대비가 가능합니다. 다만, 유출 되었을 때 위험도가 큰 Refresh-Token 을 보관하는 용도로는 쿠키가 적절하지 않기 때문에 Refresh-Token 의 사용은 포기하고 Access-Token 의 만료기간을 좀 더 늘려주는 방향으로 구현하게 되었습니다.



```java
public class CookieUtils {

    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie);
                }
            }
        }

        return Optional.empty();
    }

    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        addCookie(response, name, value, false, false, maxAge);
    }

    public static void addCookie(HttpServletResponse response, String name, String value, boolean httpOnly, boolean secure, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(httpOnly);
        cookie.setSecure(secure);
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                }
            }
        }
    }
}
```



### JWT 토큰 발급

---



JWT 토큰을 생성하고 검증하는데 사용되는 라이브러리를 추가합니다.

**build.gradle**

```java
dependencies {
	implementation 'io.jsonwebtoken:jjwt:0.9.1'
}
```



노출이 되면 안되는 키값과, 토큰 생성에 사용되는 해쉬 알고리즘, 토큰 만료시간 값을 변경이나 관리가 용이하도록 application.yml 파일에 프로퍼티로 등록하고 읽어오도록 구현하였습니다. application.yml 파일은 버전 관리에 포함되지 않는 외부 파일이어야 합니다.

**application.yml**

```yaml
jwt:
  secretKey: secret-key #jwt-secret-key
  signatureAlgorithm: HS256
  tokenExpired: 604800 #(sec) 7 days
```



만약, 프로퍼티 파일의 경로가 `/Users/me/Documents/properties/application.yml` 인 경우 프로젝트 시작시에 아래와 같이 옵션으로 프로퍼티 파일의 경로를 지정해줄 수 있습니다. 경로를 디렉토리 까지만 입력하는 경우 '/' 로 끝을 내주어야 합니다.

```shell
//경로를 모두 입력하는 경우
$ java -DSpring.config.location=file:/Users/me/Documents/properties/application.yml -jar myproject.jar

//디렉토리 까지만 입력하는 경우
$ java -DSpring.config.location=file:/Users/me/Documents/properties/ -jar myproject.jar
```



IDE 에서는 VM 옵션에 추가하여 사용할 수 있습니다.

![ide_vm_option](Login.assets/ide_vm_option.png)



**JwtProperties**

위에서 등록한 프로퍼티를 읽어와 저장하는 클래스입니다.

```java
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secretKey;
    private SignatureAlgorithm signatureAlgorithm;
    private Long tokenExpired;
}
```



**JwtProvider**

토큰을 발급하거나 토큰의 유효성을 검증하는 클래스입니다.

```java
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtProperties jwtProperties;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public LocalDateTime extractExpiration(String token) {
        return DateConvertor.toLocalDateTime(extractClaim(token, Claims::getExpiration));
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(jwtProperties.getSecretKey()).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).isBefore(LocalDateTime.now());
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return generateToken(claims, username, jwtProperties.getTokenExpired());
    }

    private String generateToken(Map<String, Object> claims, String subject, Long expiryTime) {
        LocalDateTime expiryDate = LocalDateTime.now().plusSeconds(expiryTime);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(DateConvertor.toDate(LocalDateTime.now()))
                .setExpiration(DateConvertor.toDate(expiryDate))
                .signWith(jwtProperties.getSignatureAlgorithm(), jwtProperties.getSecretKey())
                .compact();
    }

    public boolean validateToken(String token, String username) {
        final String tokenUsername = extractUsername(token);
        return (username.equals(tokenUsername) && !isTokenExpired(token));
    }

    public Long getTokenExpirationDate() {
        return jwtProperties.getTokenExpired();
    }

}
```



**JwtAuthenticationFilter**

JwtAuthenticationFilter 에서는 request 에 접근 토큰(access token) 쿠키가 포함되어 있는지 체크한 후 토큰에 포함된 회원 정보를 이용해 새로운 Authentication 인스턴스를 생성합니다. 새로 생성된 인스턴스는 이후 Security 에서 참조될 수 있도록 SecurityContext 에 추가해줍니다.

```java
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserDetailsServiceImpl userDetailsService;
    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String username = null;
        String jwt = null;

        Optional<Cookie> jwtCookie = CookieUtils.getCookie(request, "access_token");

        if(jwtCookie.isPresent()){
            jwt = jwtCookie.get().getValue();
            username = jwtProvider.extractUsername(jwt);
        }

        /**
         * 토큰에서 username 을 정상적으로 추출할 수 있고
         * SecurityContextHolder 내에 authentication 객체(이전에 인증된 정보)가 없는 상태인지를 검사한다.
         */
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(username);

            //토큰이 유효하다면
            if (jwtProvider.validateToken(jwt, userDetails.getUsername())) {
                //새로운 인증 정보를 생성
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //인증 정보를 SecurityContextHolder 에 저장
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}

```



그 다음, Security 인증 필터 보다 먼저 실행 될 수 있도록 우선순위를 설정해줍니다.

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    ...
      
    //로그인 인증을 진행하는 필터 이전에 jwtAuthenticationFilter 가 실행되도록 설정
    http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        //CSRF 필터 설정
        ...;
}
```



### 인증 호출

---



**AuthorizationRequest**

```java
@Getter
@Setter
public class AuthorizationRequest {
    @NotBlank(message = "이메일을 입력하세요.")
    private String username;
    @NotBlank(message = "패스워드를 입력하세요.")
    private String password;

    @Builder
    public AuthorizationRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }
}
```



**AuthenticationController**

유저가 로그인을 요청하면 입력한 username, password 데이터로 UsernamePasswordAuthenticationToken 인스턴스를 생성하고 AuthenticationManager 의 authenticate() 메소드의 인자로 넘겨줍니다. 그러면 UserDetailsService 인터페이스 구현체를 통해 불러온 계정 데이터를 AuthenticationProvider 구현체에서 password 가 일치하는지 체크를 진행하게 됩니다.

인증이 성공하면 authenticate() 메소드는 Authentication 인터페이스를 구현한 구현체의 인스턴스 (UsernamePasswordAuthenticationToken 클래스) 를 리턴하게 되는데 getPrincipal() 메소드를 통해 인증된 유저의 정보를 가져올 수 있습니다. 해당 정보를 이용해 토큰 쿠키를 생성하고 클라이언트에게 응답을 보내주게 됩니다.

쿠키를 생성할 때 request 객체의 isSecure() 메소드를 통해 https 프로토콜 여부를 검사하고 secure 옵션을 결정하도록 구현하였습니다.

```java
@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthenticationController {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtProvider jwtProvider;

    /* 사용자의 계정을 인증하고 로그인 토큰을 발급해주는 컨트롤러 */
    @PostMapping("/authorize")
    public void authenticateUsernamePassword(@Valid @RequestBody AuthorizationRequest authorizationRequest, BindingResult bindingResult, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if(bindingResult.hasErrors()) throw new ValidationException("로그인 유효성 검사 실패.", bindingResult.getFieldErrors());
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authorizationRequest.getUsername(), authorizationRequest.getPassword()));
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            generateTokenCookie(userDetails, request, response);
        } catch (AuthenticationException e) {
            throw new AuthenticationFailedException("아이디 또는 패스워드가 틀렸습니다.");
        }
    }
  
   private void generateTokenCookie(UserDetails userDetails, HttpServletRequest request, HttpServletResponse response) {
        final int cookieMaxAge = jwtProvider.getTokenExpirationDate().intValue();
        //https 프로토콜인 경우 secure 옵션사용
        boolean secure = request.isSecure();
        CookieUtils.addCookie(response, "access_token", jwtProvider.generateToken(userDetails.getUsername()), true, secure, cookieMaxAge);
    }
}
```



### 로그아웃

---



로그아웃시에는 접근 토큰(access token)과 CSRF 토큰 쿠키를 삭제 처리합니다.

**AuthenticationController**

```java
/* 토큰 쿠키를 삭제하는 컨트롤러 (로그아웃) */
@PostMapping("/logout")
public ResponseEntity<?> expiredToken(HttpServletRequest request, HttpServletResponse response) {
    CookieUtils.deleteCookie(request, response, "access_token");
    CookieUtils.deleteCookie(request, response, StatelessCSRFFilter.CSRF_TOKEN);
    return ResponseEntity.ok("success");
}
```

