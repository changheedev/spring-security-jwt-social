# 소셜 로그인

소셜 로그인에 사용된 클래스들은 [spring-security-oauth2-client](https://mvnrepository.com/artifact/org.springframework.security/spring-security-oauth2-client) 의 클래스들을 참고하였습니다. spring-security-oauth2-client 를 사용하여 소셜 로그인을 구현을 하다가 자체적으로 구현한 클래스들로 대체하게 된 이유는 **계정 연동, 토큰 갱신, 연동 해제 요청** 을 처리하기 위해서 입니다.



### Property 설정

---

소셜 로그인을 구현하기 위해 각 소셜 개발자 센터에 App 을 등록하고 Client-id 와 Client-secret 을 발급 받습니다.

**개발자센터 링크**

- Google : https://console.developers.google.com
- Naver : https://developers.naver.com
- Kakao: https://developers.kakao.com



발급받은 Client-id, Client-secret 과 등록한 Callback URI 를 프로퍼티로 등록합니다.

```yml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: #client-id
            client-secret: #client-secret
            authorization-grant-type: authorization_code
            redirect-uri: #callback uri
            scope:
              - profile
              - email
          naver:
            client-id: #client-id
            client-secret: #client-secret
            authorization-grant-type: authorization_code
            redirect-uri: #callback uri
            scope:
              - profile
          kakao:
            client-id: #client-id
            client-secret: #client-secret
            authorization-grant-type: authorization_code
            redirect-uri: #callback uri
            scope:
              - profile
              - account_email
        provider:
          google:
            authorization-uri: https://accounts.google.com/o/oauth2/auth
            token-uri: https://www.googleapis.com/oauth2/v4/token
            user-info-uri: https://www.googleapis.com/oauth2/v2/userinfo
            unlink-uri: https://accounts.google.com/o/oauth2/revoke
          naver:
            authorization-uri: https://nid.naver.com/oauth2.0/authorize
            token-uri: https://nid.naver.com/oauth2.0/token
            user-info-uri: https://openapi.naver.com/v1/nid/me
            unlink-uri: https://nid.naver.com/oauth2.0/token
          kakao:
            authorization-uri: https://kauth.kakao.com/oauth/authorize
            token-uri: https://kauth.kakao.com/oauth/token
            user-info-uri: https://kapi.kakao.com/v2/user/me
            unlink-uri: https://kapi.kakao.com/v1/user/unlink
```



OAuth 프로퍼티를 매핑하는 클래스 입니다. 모든 소셜 서비스의 프로퍼티가 저장되며 다음과 같은 형태로 프로퍼티가 매핑 됩니다. 

**registration** : spring.security.oauth2.client.registration 에 해당하는 프로퍼티로,  "google", "naver", "kakao" 의 키값으로 매핑.

**provider** :  spring.security.oauth2.client.provider 에 해당하는 프로퍼티로,  "google", "naver", "kakao" 의 키값으로 매핑.

```java
@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.client")
public class OAuth2ClientProperties {

    private final Map<String, Provider> provider = new HashMap<>();
    private final Map<String, Registration> registration = new HashMap<>();

    public Map<String, Provider> getProvider() {
        return this.provider;
    }
    public Map<String, Registration> getRegistration() {
        return this.registration;
    }

    /**
     * A single client registration.
     */
    @Getter
    @Setter
    public static class Registration {
        private String provider;
        private String clientId;
        private String clientSecret;
        private String authorizationGrantType;
        private String redirectUri;
        private Set<String> scope;
    }

    @Getter
    @Setter
    public static class Provider {
        private String authorizationUri;
        private String tokenUri;
        private String userInfoUri;
        private String unlinkUri;
    }
}
```



각 소셜 서비스에 대한 프로퍼티를 파싱하여 매핑하는 클래스 입니다.

```java
@Getter
@Setter
public final class ClientRegistration {
    private String registrationId;
    private String clientId;
    private String clientSecret;
    private String authorizationGrantType;
    private String redirectUri;
    private Set<String> scopes = Collections.emptySet();
    private ProviderDetails providerDetails = new ProviderDetails();

    @Builder
    public ClientRegistration(String registrationId, String clientId, String authorizationGrantType, String clientSecret, String redirectUri, Set<String> scopes, String authorizationUri, String tokenUri, String userInfoUri, String unlinkUri) {
        this.registrationId = registrationId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.authorizationGrantType = authorizationGrantType;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.providerDetails.authorizationUri = authorizationUri;
        this.providerDetails.tokenUri = tokenUri;
        this.providerDetails.userInfoUri = userInfoUri;
        this.providerDetails.unlinkUri = unlinkUri;
    }

    @Getter
    @Setter
    public class ProviderDetails {
        private String authorizationUri;
        private String tokenUri;
        private String userInfoUri;
        private String unlinkUri;
    }
}
```



각 소셜 서비스의 프로퍼티가 저장된 ClientRegistration 인스턴스들을 저장하는 저장소 클래스 입니다. 이후 소셜 인증을 진행할 때 이 저장소에서 해당 소셜 서비스의 프로퍼티 정보를 담고있는 ClientRegistration 인스턴스를 꺼내온 후 사용하게 됩니다.

```java
public class ClientRegistrationRepository {
    private final Map<String, ClientRegistration> registrations;

    public ClientRegistrationRepository(Map<String, ClientRegistration> registrations) {
        this.registrations = registrations;
    }

    public ClientRegistrationRepository(List<ClientRegistration> registrations) {
        this(createRegistrationsMap(registrations));
    }

    private static Map<String, ClientRegistration> createRegistrationsMap(List<ClientRegistration> registrations) {
        return toUnmodifiableConcurrentMap(registrations);
    }

    private static Map<String, ClientRegistration> toUnmodifiableConcurrentMap(List<ClientRegistration> registrations) {
        ConcurrentHashMap<String, ClientRegistration> result = new ConcurrentHashMap<>();
        for (ClientRegistration registration : registrations)
            result.put(registration.getRegistrationId(), registration);
        return Collections.unmodifiableMap(result);
    }

    public ClientRegistration findByRegistrationId(String registrationId) {
        return this.registrations.get(registrationId);
    }
}
```



이용할 수 있는 소셜 서비스 리스트를 enum 클래스로 관리합니다. 각 소셜 서비스의 ClientRegistration 인스턴스를 만들기 위한 getBuilder() 메소드를 포함하고 있습니다.

```java
public enum CustomOAuth2Provider {
    GOOGLE, KAKAO, NAVER;

    public ClientRegistration.ClientRegistrationBuilder getBuilder(String registrationId) {
        return ClientRegistration.builder().registrationId(registrationId);
    }
}
```



애플리케이션이 초기화 되는 과정에서 ClientRegistrationRepository 에 각 소셜 서비스 ClientRegistration 인스턴스들을 생성하여 저장하고 Bean으로 등록합니다.

```java
@Configuration
@RequiredArgsConstructor
public class OAuth2Configurer {

    private final OAuth2ClientProperties oAuth2ClientProperties;

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {

        List<ClientRegistration> registrations = oAuth2ClientProperties.getRegistration().keySet().stream()
                .map(c -> getRegistration(c))
                .filter(registration -> registration != null)
                .collect(Collectors.toList());

        return new ClientRegistrationRepository(registrations);
    }

    private ClientRegistration getRegistration(String client) {
        if (client.equals("google")) {
            return CustomOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(oAuth2ClientProperties.getRegistration().get(client).getClientId())
                    .clientSecret(oAuth2ClientProperties.getRegistration().get(client).getClientSecret())
                    .authorizationGrantType(oAuth2ClientProperties.getRegistration().get(client).getAuthorizationGrantType())
                    .redirectUri(oAuth2ClientProperties.getRegistration().get(client).getRedirectUri())
                    .scopes(oAuth2ClientProperties.getRegistration().get(client).getScope())
                    .authorizationUri(oAuth2ClientProperties.getProvider().get(client).getAuthorizationUri())
                    .tokenUri(oAuth2ClientProperties.getProvider().get(client).getTokenUri())
                    .userInfoUri(oAuth2ClientProperties.getProvider().get(client).getUserInfoUri())
                    .unlinkUri(oAuth2ClientProperties.getProvider().get(client).getUnlinkUri())
                    .build();
        }
        if (client.equals("naver")) {
           return ...
        }
        if (client.equals("kakao")) {
            return ...
        }
        return null;
    }
}
```



### OAuth 서버와의 통신 구현

---

RestTemplate 을 이용하여 소셜 인증 서버와의 통신을 담당하는 OAuth2Service 클래스를 만들어 보도록 하겠습니다.

**인증 페이지 요청, 토큰 요청, 토큰 갱신 요청, 유저 정보 요청**은 모든 소셜 서비스가 비슷하게 처리를 하고 있어서 공통 메소드로 구현했지만, 연결 해제 요청의 경우 각 소셜 서비스마다 호출에 사용되는 메소드, 파라미터 등이 상이하여 별도로 구현을 해야만 했습니다. 이 부분을 처리하기 위해 unlink() 메소드를 abstract 타입으로 선언하고 서브 클래스에서 unlink() 메소드를 구현합니다.

한가지 더 주의 할 부분은 토큰 갱신 요청의 경우 공통 메소드로 구현하고 있지만, 네이버의 경우 토큰을 갱신할 때 리프레쉬 토큰은 응답 데이터에 포함되지 않기 때문에 예외 처리를 해주어야 합니다.

```java
public abstract class OAuth2Service {

    protected final Logger log = LoggerFactory.getLogger(this.getClass());
    protected final RestTemplate restTemplate;

    public OAuth2Service(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

  
  	//인증 페이지 요청
    public void redirectAuthorizePage(ClientRegistration clientRegistration, String state, HttpServletResponse response) throws IOException {
        String authorizationUri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getAuthorizationUri())
                .queryParam("client_id", clientRegistration.getClientId())
                .queryParam("response_type", "code")
                .queryParam("access_type", "offline") //refresh token 을 받기 위한 옵션 : for google
                .queryParam("include_granted_scopes", true) // for google
                .queryParam("scope", String.join("+", clientRegistration.getScopes()))
                .queryParam("state", state)
                .queryParam("redirect_uri", clientRegistration.getRedirectUri())
                .build().encode(StandardCharsets.UTF_8).toUriString();
        response.sendRedirect(authorizationUri);
    }
		
  	//인증 토큰 요청
    public OAuth2Token getAccessToken(ClientRegistration clientRegistration, String code, String state) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientRegistration.getClientId());
        params.add("client_secret", clientRegistration.getClientSecret());
        params.add("grant_type", clientRegistration.getAuthorizationGrantType());
        params.add("code", code);
        params.add("state", state);
        params.add("redirect_uri", clientRegistration.getRedirectUri());

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(params, headers);

        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(clientRegistration.getProviderDetails().getTokenUri(), HttpMethod.POST, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2RequestFailedException(String.format("%s 토큰 요청 실패 [응답코드 : %d].", clientRegistration.getRegistrationId().toUpperCase(), statusCode), exception);
        }

        log.debug(entity.getBody());
        JsonObject jsonObj = JsonUtils.parse(entity.getBody()).getAsJsonObject();
        String accessToken = jsonObj.get("access_token").getAsString();
        String refreshToken = jsonObj.get("refresh_token").getAsString();
        LocalDateTime expiredAt = LocalDateTime.now().plusSeconds(jsonObj.get("expires_in").getAsLong());

        return new OAuth2Token(accessToken, refreshToken, expiredAt);
    }
  
  
		//토큰 갱신 요청
    protected OAuth2Token refreshOAuth2Token(ClientRegistration clientRegistration, OAuth2Token token) {

        //토큰이 만료되지 않았다면 원래 토큰을 리턴
        if (LocalDateTime.now().isBefore(token.getExpiredAt())) return token;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientRegistration.getClientId());
        params.add("client_secret", clientRegistration.getClientSecret());
        params.add("grant_type", "refresh_token");
        params.add("refresh_token", token.getRefreshToken());

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(params, headers);

        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(clientRegistration.getProviderDetails().getTokenUri(), HttpMethod.POST, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2RequestFailedException(String.format("%s 토큰 갱신 실패 [응답코드 : %d].", clientRegistration.getRegistrationId().toUpperCase(), statusCode), exception);
        }

        JsonObject jsonObj = JsonUtils.parse(entity.getBody()).getAsJsonObject();
        String accessToken = jsonObj.get("access_token").getAsString();
        //naver의 경우는 null
        String newRefreshToken = jsonObj.get("refresh_token").getAsString();
        LocalDateTime expiredAt = LocalDateTime.now().plusSeconds(jsonObj.get("expires_in").getAsLong());

        return new OAuth2Token(accessToken, newRefreshToken != null ? newRefreshToken : token.getRefreshToken(), expiredAt);
    }

    public OAuth2UserInfo getUserInfo(ClientRegistration clientRegistration, String accessToken) {

        HttpHeaders headers = new HttpHeaders();

        headers.add("Authorization", "Bearer " + accessToken);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<?> httpEntity = new HttpEntity<>(headers);

        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(clientRegistration.getProviderDetails().getUserInfoUri(), HttpMethod.GET, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2RequestFailedException(String.format("%s 유저 정보 요청 실패 [응답코드 : %d].", clientRegistration.getRegistrationId().toUpperCase(), statusCode), exception);
        }

        Map<String, Object> userAttributes = JsonUtils.fromJson(entity.getBody(), Map.class);

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(clientRegistration.getRegistrationId(), userAttributes);

        return userInfo;
    }

    public abstract void unlink(ClientRegistration clientRegistration, OAuth2Token token);
```



**unlink() 메소드 구현**

```java
public class GoogleOAuth2Service extends OAuth2Service{
    public GoogleOAuth2Service(RestTemplate restTemplate) {
        super(restTemplate);
    }

    @Override
    public void unlink(ClientRegistration clientRegistration, OAuth2Token token){

        //토큰이 만료되었다면 토큰을 갱신
        token = refreshOAuth2Token(clientRegistration, token);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(headers);

        String unlinkUri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getUnlinkUri())
                .queryParam("token", token.getToken()).encode().build().toUriString();

        ResponseEntity<String> entity = null;
        try {
            entity = restTemplate.exchange(unlinkUri, HttpMethod.GET, httpEntity, String.class);
        } catch (HttpStatusCodeException exception) {
            int statusCode = exception.getStatusCode().value();
            throw new OAuth2RequestFailedException(String.format("%s 연동해제 실패. [응답코드 : %d].", clientRegistration.getRegistrationId().toUpperCase(), statusCode), exception);
        }
    }
}
```



요청에 따라 OAuth2Service 의 서브 클래스 인스턴스를  생성하기 위해 Factory 패턴을 사용하였습니다.

```java
public class OAuth2ServiceFactory {
    public static OAuth2Service getOAuth2Service(RestTemplate restTemplate, String registrationId) {

        if (registrationId.equalsIgnoreCase("google"))
            return new GoogleOAuth2Service(restTemplate);
        if (registrationId.equalsIgnoreCase("naver"))
            return new NaverOAuth2Service(restTemplate);
        if (registrationId.equalsIgnoreCase("kakao"))
            return new KakaoOAuth2Service(restTemplate);
        else
            throw new IllegalArgumentException(registrationId.toUpperCase() + " 로그인은 지원하지 않습니다.");
    }
}
```



### 소셜 인증 요청

---

클라이언트에서는 인증 성공 후 이동할 페이지와 callback 타입을 파라미터로 추가하여 소셜 인증을 요청하게 됩니다. 

```
http://localhost:8080/api/oauth2/authorize/google?redirect_uri=http://localhost:3000/mypage&callback=login(or 'link')
```



이 정보들은 현재의 인증 요청에 대한 흐름에서만 필요한 정보이므로 임시로 저장할 수만 있으면 되는데, Session 을 사용하지 않기 때문에 메모리 상에 상주하고 있는 저장소를 만들었고, 이 저장소에 state 값을 key 로 하여 저장하도록 구현하였습니다. 그리고 항상 같은 데이터를 참조할 수 있도록 싱글톤 패턴으로 관리하기 위해 Component 로 등록하였습니다.

추가로 유저가 소셜 로그인을 취소하는 경우 유저의 페이지를 다시 원래 페이지로 리디렉션 시켜주기 위해 referer 정보도 함께 저장합니다.

```java
/* 사용자의 소셜 로그인 요청을 받아 각 소셜 서비스로 인증을 요청하는 컨트롤러 */
@GetMapping("/oauth2/authorize/{provider}")
public void redirectSocialAuthorizationPage(@PathVariable String provider, @RequestParam(name = "redirect_uri") String redirectUri, @RequestParam String callback, HttpServletRequest request, HttpServletResponse response) throws Exception {
    String state = generateState();

    // 콜백에서 사용할 요청 정보를 저장
    inMemoryOAuth2RequestRepository.saveOAuth2Request(state, OAuth2AuthorizationRequest.builder().referer(request.getHeader("referer")).redirectUri(redirectUri).callback(callback).build());

    ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);
    OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, provider);
    oAuth2Service.redirectAuthorizePage(clientRegistration, state, response);
}
```



```java
@Component
public class InMemoryOAuth2RequestRepository {
    private Map<String, OAuth2AuthorizationRequest> oAuth2RequestMap = new HashMap<>();

    public void saveOAuth2Request(String state, OAuth2AuthorizationRequest oAuth2AuthorizationRequest){
        oAuth2RequestMap.put(state, oAuth2AuthorizationRequest);
    }

    public OAuth2AuthorizationRequest getOAuth2Request(String state){
        return oAuth2RequestMap.get(state);
    }

    public OAuth2AuthorizationRequest deleteOAuth2Request(String state){
        return oAuth2RequestMap.remove(state);
    }
}
```



### Callback

---

Callback URL 은 개발자 센터에 등록했던 Callback URL 과 동일하게 설정합니다.

OAuth 인증 서버에서는 인증에 성공하면 authorization_code 와 인증을 요청할 때 파라미터로 보냈던 state 를 파라미터로 해서 Callback 을 호출해줍니다. 만약, 도중에 유저가 로그인을 취소하거나 기타 다른 오류가 발생하게 되면 error 데이터를 포함하여 Callback 을 호출합니다.

인증에 성공했다면, authorization_code 와 state 를 이용하여 OAuth 인증 서버로 Access Token 을 요청하고 토큰을 발급 받는데 성공하면 토큰을 이용하여 UserInfo 를 요청하여 받아옵니다. 이때 발급 받은 토큰은 소셜 계정 정보와 함께 저장하게 되는데 이후 연동 해제 요청을 보낼때 사용됩니다.

```java
/* 각 소셜 서비스로부터 인증 결과를 처리하는 컨트롤러 */
@RequestMapping("/oauth2/callback/{provider}")
public void oAuth2AuthenticationCallback(@PathVariable String provider, OAuth2AuthorizationResponse oAuth2AuthorizationResponse, HttpServletRequest request, HttpServletResponse response, @AuthenticationPrincipal UserDetailsImpl loginUser) throws Exception {

    //인증을 요청할 때 저장했던 request 정보를 가져온다.
    OAuth2AuthorizationRequest oAuth2AuthorizationRequest = inMemoryOAuth2RequestRepository.deleteOAuth2Request(oAuth2AuthorizationResponse.getState());

    //유저가 로그인 페이지에서 로그인을 취소하거나 오류가 발생했을때 처리
    if (oAuth2AuthorizationResponse.getError() != null) {
        redirectWithErrorMessage(oAuth2AuthorizationRequest.getReferer(), oAuth2AuthorizationResponse.getError(), response);
        return;
    }

    //사용자의 요청에 맞는 OAuth2 클라이언트 정보를 매핑한다
    ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(provider);
    OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, provider);

    //토큰과 유저 정보를 요청
    OAuth2Token oAuth2Token = oAuth2Service.getAccessToken(clientRegistration, oAuth2AuthorizationResponse.getCode(), oAuth2AuthorizationResponse.getState());
    OAuth2UserInfo oAuth2UserInfo = oAuth2Service.getUserInfo(clientRegistration, oAuth2Token.getToken());

    //로그인에 대한 콜백 처리
    if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("login")) {
        UserDetails userDetails = userService.loginOAuth2User(provider, oAuth2Token, oAuth2UserInfo);
        generateTokenCookie(userDetails, request, response);
        generateCSRFTokenCookie(response);
    }
    //계정 연동에 대한 콜백 처리
    else if (oAuth2AuthorizationRequest.getCallback().equalsIgnoreCase("link")) {
        //로그인 상태가 아니면
        if (loginUser == null) {
            redirectWithErrorMessage(oAuth2AuthorizationRequest.getReferer(), "unauthorized", response);
            return;
        }
        try {
            userService.linkOAuth2Account(loginUser.getUsername(), provider, oAuth2Token, oAuth2UserInfo);
        } catch (Exception e) {
            redirectWithErrorMessage(oAuth2AuthorizationRequest.getReferer(), e.getMessage(), response);
            return;
        }
    }

    //콜백 성공
    response.sendRedirect(oAuth2AuthorizationRequest.getRedirectUri());
}
```



#### 1) 로그인 Callback 처리

소셜 로그인의 경우 아래와 같은 경우의 수가 존재합니다.



1. 새로 로그인 하는 경우

   - 중복된 이메일로 가입된 계정이 존재하는 경우

   - 중복된 이메일로 가입된 계정이 존재하지 않는 경우

2. 재 로그인 하는 경우



각 경우에 대해서 다음과 같이 처리합니다.



1. 새로 로그인 하는 경우

   - 중복된 이메일로 가입된 계정이 존재하는 경우 **=> 소셜 계정을 생성하고 해당 계정과 연동처리**

   - 중복된 이메일로 가입된 계정이 존재하지 않는 경우 **=> 소셜 계정을 생성하고 새로운 계정으로 가입 & 연동처리**

2. 재 로그인 하는 경우 **=> 소셜 계정과 연동된 계정 정보를 불러오고 토큰 갱신**



또한, 소셜 계정 정보를 이용해 새로운 계정으로 가입하는 경우 Email 정보가 포함되어 있지 않을 수도 있기 때문에 Email 대신 '{provider}_{socialId}' 형태로 Username 을 생성해 주고, UserType 을 OAUTH 로 저장합니다.

```java
		@Override
    public UserDetails loginOAuth2User(String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo) {

        Optional<OAuth2Account> optOAuth2Account = oAuth2AccountRepository.findByProviderAndProviderId(provider, userInfo.getId());
        User user = null;

        //가입된 계정이 존재할때
        if (optOAuth2Account.isPresent()) {
            OAuth2Account oAuth2Account = optOAuth2Account.get();
            user = oAuth2Account.getUser();
            //토큰 업데이트
            oAuth2Account.updateToken(oAuth2Token.getToken(), oAuth2Token.getRefreshToken(), oAuth2Token.getExpiredAt());
        }
        //가입된 계정이 존재하지 않을때
        else {
            //소셜 계정 정보 생성
            OAuth2Account newAccount = OAuth2Account.builder()
                    .provider(provider)
                    .providerId(userInfo.getId())
                    .token(oAuth2Token.getToken())
                    .refreshToken(oAuth2Token.getRefreshToken())
                    .tokenExpiredAt(oAuth2Token.getExpiredAt()).build();
            oAuth2AccountRepository.save(newAccount);

            //이메일 정보가 있을때
            if (userInfo.getEmail() != null) {
                // 같은 이메일을 사용하는 계정이 존재하는지 확인 후 있다면 소셜 계정과 연결시키고 없다면 새로 생성한다
                user = userRepository.findByEmail(userInfo.getEmail())
                        .orElse(User.builder()
                                .username(provider + "_" + userInfo.getId())
                                .name(userInfo.getName())
                                .email(userInfo.getEmail())
                                .type(UserType.OAUTH)
                                .build());
            }
            //이메일 정보가 없을때
            else {
                user = User.builder()
                        .username(provider + "_" + userInfo.getId())
                        .name(userInfo.getName())
                        .type(UserType.OAUTH)
                        .build();
            }

            //새로 생성된 유저이면 db에 저장
            if (user.getId() == null)
                userRepository.save(user);

            //연관관계 설정
            user.linkSocial(newAccount);
        }

        return UserDetailsImpl.builder()
                .id(user.getId())
                .username(user.getUsername())
                .name(user.getName())
                .email(user.getEmail())
                .type(user.getType())
                .authorities(user.getAuthorities()).build();
    }
```



#### 2) 계정 연동 Callback 처리

새로운 소셜 계정을 생성하고 로그인된 유저의 계정과 연동합니다.

```java
		@Override
    public UserDetails linkOAuth2Account(String username, String provider, OAuth2Token oAuth2Token, OAuth2UserInfo userInfo) {
        User user = checkRegisteredUser(username);
        //이미 등록된 소셜 계정이라면 연동된 계정이 존재
        Assert.state(oAuth2AccountRepository.existsByProviderAndProviderId(provider, userInfo.getId()) == false, "소셜 계정에 연동된 계정이 이미 존재합니다.");

        //소셜 계정 정보 생성
        OAuth2Account oAuth2Account = OAuth2Account.builder()
                .provider(provider)
                .providerId(userInfo.getId())
                .token(oAuth2Token.getToken())
                .refreshToken(oAuth2Token.getRefreshToken())
                .tokenExpiredAt(oAuth2Token.getExpiredAt())
                .build();
        oAuth2AccountRepository.save(oAuth2Account);

        //연관관계 설정
        user.linkSocial(oAuth2Account);

        return UserDetailsImpl.builder()
                .id(user.getId())
                .username(user.getUsername())
                .name(user.getName())
                .email(user.getEmail())
                .type(user.getType())
                .authorities(user.getAuthorities()).build();
    }

		private User checkRegisteredUser(String username) {
        Optional<User> optUser = userRepository.findByUsername(username);
        Assert.state(optUser.isPresent(), "가입되지 않은 회원입니다.");
        return optUser.get();
    }
```



**엔티티 연관관계 설정**

하나의 계정에는 하나의 소셜 계정만 연동이 가능하므로 User 엔티티와 OAuth2Account 엔티티를 일대일 매핑하는데 경우에 따라 양방향 참조가 필요하므로 일대일 양방향 매핑으로 설정합니다. 그리고 User 테이블에서 외래키를 관리하도록 User 엔티티를 연관 관계의 주인으로 설정합니다. (OAuth2Account 에 mappedBy 사용)

```java
public class User extends BaseEntity {
  
  	...

    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "SOCIAL_ID")
    private OAuth2Account social;
		  
    public void linkSocial(OAuth2Account oAuth2Account) {
        Assert.state(social == null, "하나의 소셜 서비스만 연동할 수 있습니다.");
        this.social = oAuth2Account;
        oAuth2Account.linkUser(this);
    }
}

```

```java
@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "TBL_OAUTH_ACCOUNT", uniqueConstraints = {@UniqueConstraint(columnNames = {"provider", "providerId"})})
public class OAuth2Account extends BaseEntity {
    private String providerId;
    private String provider;
    private String token;
    private String refreshToken;
    private LocalDateTime tokenExpiredAt;
    @OneToOne(mappedBy = "social")
    private User user;

    @Builder
    public OAuth2Account(String providerId, String provider, String token, String refreshToken, LocalDateTime tokenExpiredAt) {
        this.providerId = providerId;
        this.provider = provider;
        this.token = token;
        this.refreshToken = refreshToken;
        this.tokenExpiredAt = tokenExpiredAt;
    }

    public void updateToken(String token, String refreshToken, LocalDateTime tokenExpiredAt) {
        this.token = token;
        this.refreshToken = refreshToken;
        this.tokenExpiredAt = tokenExpiredAt;
    }

    public void linkUser(User user) {
        Assert.state(this.user == null, "소셜 계정에 연동 된 다른 계정이 존재합니다.");
        this.user = user;
    }

    public OAuth2AccountDTO toDTO() {
        return OAuth2AccountDTO.builder()
                .provider(provider)
                .providerId(providerId)
                .createAt(getCreateAt())
                .token(token)
                .refreshToken(refreshToken)
                .tokenExpiredAt(tokenExpiredAt).build();
    }
}
```

