# Security 설정

---



**SecurityConfigurer**

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션 사용 x
                .and()
                .csrf().disable()
                .cors().disable()
                .formLogin().disable()
                .logout().disable()
                .httpBasic().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().authenticated().and()
                .exceptionHandling()
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));

      	//CSRF 필터 설정
      	http.addFilterBefore(new StatelessCSRFFilter(), CsrfFilter.class);
    }
}
```



**SessionCreationPolicy.STATELESS** 

토큰 인증 방식에서는 세션을 사용하지 않기 때문에 세션 생성 정책을 STATELESS 로 설정합니다.

Security 에서 제공하는 기본 로그인과 로그아웃을 비활성화 시켜주었습니다.



**HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)**

또한, 시큐리티에서 기본적으로 인증 실패 및 권한 문제 등의 Exception 처리에 403 응답코드를 사용하고 있는데 인증 실패에 대해서는 401 응답코드를 사용하도록 authenticationEntryPoint() 설정을 해주었습니다.





## CSRF

---



인증 토큰을 쿠키로 발급하게 되면 CSRF 공격에 노출된다는 문제점이 있기 때문에 이에 대한 방지 처리를 해주어야 합니다. 

CSRF 토큰을 이용한 CSRF 공격 방지 처리를 구현해보도록 하겠습니다.

전체적인 흐름은 서버에서 클라이언트에게 CSRF 토큰 값이 담긴 쿠키를 발급하고, 클라이언트에서는 CSRF 공격에 대한 보호가 필요한 API 를 호출할때는 쿠키에서 토큰 값을 읽어 헤더에 추가한 뒤 API 를 호출하게 됩니다. 

이는 CSRF 공격자는 요청 헤더를 추가 할 수 없다는 점을 이용하는 방법입니다. 



**StatelessCSRFFilter**

```java
public class StatelessCSRFFilter extends OncePerRequestFilter {

    public static final String CSRF_TOKEN = "CSRF-TOKEN";
    public static final String X_CSRF_TOKEN = "X-CSRF-TOKEN";
    private final RequestMatcher requireCsrfProtectionMatcher = new DefaultRequiresCsrfMatcher();
    private final AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandlerImpl();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        //csrf 보호가 필요한 method 인지 확인
        if (requireCsrfProtectionMatcher.matches(request)) {
            Optional<String> optCsrfToken = Optional.ofNullable(request.getHeader(X_CSRF_TOKEN));
            Optional<Cookie> optCsrfCookie = CookieUtils.getCookie(request, CSRF_TOKEN);

            if (!optCsrfCookie.isPresent() || !optCsrfToken.isPresent() || !optCsrfToken.get().equals(optCsrfCookie.get().getValue())) {
                accessDeniedHandler.handle(request, response, new AccessDeniedException(
                        "CSRF 토큰이 유효하지 않습니다."));
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    public static final class DefaultRequiresCsrfMatcher implements RequestMatcher {
        private final Pattern allowedMethods = Pattern.compile("^(GET|HEAD|TRACE|OPTIONS)$");

        @Override
        public boolean matches(HttpServletRequest request) {
            return !allowedMethods.matcher(request.getMethod()).matches();
        }
    }
}
```



CSRF 토큰은 클라이언트에서 직접 요청할 때와 로그인에 성공했을때 발급하도록 구현했습니다. 

직접 요청에 대한 부분을 처리한 이유는 대부분 공격에 대한 보호가 필요한 API 는 로그인 상태에서 호출되지만, 미인증 상태에서 호출되는 로그인과 회원 가입 API 역시 POST 메소드를 이용하는 보호가 필요한 요청이기 때문입니다. 

**AuthenticationController**

```java
public class AuthenticationController {
  
		@GetMapping("/csrf-token")
    public ResponseEntity<?> getCsrfToken(HttpServletRequest request, HttpServletResponse response) {
        String csrfToken = UUID.randomUUID().toString();

        Map<String, String> resMap = new HashMap<>();
        resMap.put(StatelessCSRFFilter.CSRF_TOKEN, csrfToken);

        generateCSRFTokenCookie(response);
        return ResponseEntity.ok(resMap);
    }


		/* 사용자의 계정을 인증하고 로그인 토큰을 발급해주는 컨트롤러 */
    @PostMapping("/authorize")
    public void authenticateUsernamePassword(...) throws IOException {
					... 
          generateTokenCookie(userDetails, response);
          generateCSRFTokenCookie(response); //CSRF 토큰 쿠키 발급 추가
        
    }


		/* 각 소셜 서비스로부터 인증 결과를 처리하는 컨트롤러 */
    @RequestMapping("/oauth2/callback/{provider}")
    public void oAuth2AuthenticationCallback(...) throws Exception {

     		...
        //로그인에 대한 콜백 처리
        if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("login")) {
            UserDetails userDetails = userService.loginOAuth2User(provider, oAuth2Token, oAuth2UserInfo);
            generateTokenCookie(userDetails, response);
            generateCSRFTokenCookie(response); //CSRF 토큰 쿠키 발급 추가
    }
      
    private void generateCSRFTokenCookie(HttpServletResponse response) {
        CookieUtils.addCookie(response, StatelessCSRFFilter.CSRF_TOKEN, UUID.randomUUID().toString(), 60 * 60 * 24);
    }

}

```



클라이언트에서는 서버사이드에서 앱 초기화를 진행할때와 페이지의 이동이 일어날 때 CSRF 토큰 쿠키가 존재하는지 확인하고 없으면 서버에 요청하게 됩니다. 

**client/store/index.js**

```js
export const actions = {
  //서버 사이드에서 앱을 초기화 할때 호출된다
  async nuxtServerInit({ commit }, { app }) {
    //CSRF 쿠키가 없으면 서버에 CSRF 토큰을 요청하고 쿠키를 생성
    if (!app.$cookies.get("CSRF-TOKEN")) {
      const csrfToken = await app.$axios.$get(process.env.apis.auth.csrf.uri);
      //브라우저 객체에는 클라이언트 사이드에서만 접근이 가능하므로 서버 사이드에서 실행되는 현재 시점에서는 
      //서버로 부터 받은 쿠키를 브라우저에 저장할 수 없기 때문에 쿠키를 새로 생성해준다.
      app.$cookies.set("CSRF-TOKEN", csrfToken["CSRF-TOKEN"], {
        path: "/",
        maxAge: 60 * 60 * 24
      });
    }
  }
}
```



**client/middleware/csrf.js**

```js
//클라이언트 사이드에서 CSRF 토큰 쿠키를 확인하는 미들웨어
export default function({ app }) {
  if (process.server || app.$cookies.get("CSRF-TOKEN")) return;
  app.$axios.$get(process.env.apis.auth.csrf.uri);
}
```



**nuxt.config.js**

```js
//페이지 이동이 발생할때마다 CSRF 토큰 쿠키를 확인하는 미들웨어가 실행되도록 설정
router: {
   middleware: "csrf"
}
```



API를 호출할 때에는 인터셉터를 이용해 CSRF 토큰 헤더가 필요한 요청인지 확인한 후 쿠키에서 토큰 값을 읽어와 헤더에 추가하여 요청을 진행합니다.

**client/plugins/axios.js**

```js
export default function({ app }) {
 	//axios로 요청을 보낼때 실행되는 인터셉터
  app.$axios.onRequest(config => {
    if (!config.method.toUpperCase().match(/^(GET|HEAD|TRACE|OPTIONS)$/)) {
      let csrfToken = app.$cookies.get("CSRF-TOKEN");
      config.headers.common["X-CSRF-TOKEN"] = csrfToken;
    }
  });
}
```



## CORS

---

CORS 설정은 각 환경에 따라 허용하는 Origin 도메인을 적용할 수 있도록 프로퍼티에서 읽어오도록 구현했습니다.

**application.yml**

```yml
client:
  origins: http://localhost:3000
```

**MvcConfigurer**

```java
@Configuration
public class MvcConfigurer implements WebMvcConfigurer {

    @Value("${client.origins}")
    private String[] allowedOrigins;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(allowedOrigins)
                .allowedMethods(
                        HttpMethod.GET.name(),
                        HttpMethod.HEAD.name(),
                        HttpMethod.POST.name(),
                        HttpMethod.PUT.name(),
                        HttpMethod.DELETE.name())
                .maxAge(3600)
                .allowCredentials(true);
    }
}
```



