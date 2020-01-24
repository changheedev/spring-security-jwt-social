# 회원탈퇴

---

탈퇴하려는 회원의 계정에 연동된 소셜 서비스가 있다면 해당 서비스에도 연동 해제 요청을 보내야 합니다. 연동 해제 요청을 보내기 위해서는 소셜 계정 데이터가 필요하므로 소셜 서비스 연동 여부에 따라 소셜 계정 데이터를 리턴하게 됩니다.

**UserService**

```java
@Override
public Optional<OAuth2AccountDTO> withdrawUser(String username) {
    OAuth2AccountDTO oAuth2AccountDTO = null;
    User user = checkRegisteredUser(username);
    //연동된 소셜 계정이 있다면 계정 정보를 리턴하기 위해 저장
    if(user.getSocial() != null)
        oAuth2AccountDTO = user.getSocial().toDTO();
    userRepository.delete(user);
    return Optional.ofNullable(oAuth2AccountDTO);
}
```



컨트롤러에서는 서비스 레이어에서 리턴된 소셜 계정 정보를 확인 후 해당 정보를 이용해 연동 해제 요청을 보냅니다. 

모든 과정이 완료되면 접근 토큰(access token) 쿠키와 CSRF 토큰 쿠키를 지워 로그아웃 처리를 합니다.

**UserController**

```java
@DeleteMapping("/withdraw")
public void withdrawUser(@AuthenticationPrincipal UserDetailsImpl loginUser, HttpServletRequest request, HttpServletResponse response) {
    Optional<OAuth2AccountDTO> optionalOAuth2AccountDTO = userService.withdrawUser(loginUser.getUsername());
    //연동된 소셜계정 정보가 있다면 연동해제 요청
    if(optionalOAuth2AccountDTO.isPresent()) {
        OAuth2AccountDTO oAuth2AccountDTO = optionalOAuth2AccountDTO.get();
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(oAuth2AccountDTO.getProvider());
        OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, oAuth2AccountDTO.getProvider());
        oAuth2Service.unlink(clientRegistration, oAuth2AccountDTO.getOAuth2Token());
    }
    CookieUtils.deleteCookie(request, response, "access_token");
    CookieUtils.deleteCookie(request, response, StatelessCSRFFilter.CSRF_TOKEN);
}
```

