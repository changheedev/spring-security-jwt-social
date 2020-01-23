# 연동 해제

연동해제는 다음과 같은 순서로 진행됩니다.

1. User 엔티티와 OAuth2Account 엔티티의 연관 관계를 해제
2. 소셜 계정 정보(OAuth2Account 엔티티) 삭제
3. OAuth 인증 서버에 연결 해제 요청



로그인과 달리 OAuth 인증 서버에 요청을 마지막에 보내는 것은 엔티티 간의 연관 관계를 해제하고 소셜 계정 정보를 삭제하는 과정이 모두 정상적으로 완료되었을 때에만 소셜 계정을 App 에서 연결 해제 시키기 위해서 입니다. 



#### 연관관계 해제 & 소셜 계정 정보 삭제

연관 관계를 해제하는 과정에서 해당 계정이 소셜 로그인을 통해 가입된 계정인지 체크하게 됩니다. 소셜 로그인으로 가입된 계정은 연동을 해제하게 되면 로그인을 할 수 없기 때문에 연동 해제 요청을 거부처리 합니다.

```java
    @PostMapping("/oauth2/unlink")
    public void unlinkOAuth2Account(@AuthenticationPrincipal UserDetailsImpl loginUser) {

        OAuth2AccountDTO oAuth2AccountDTO = userService.unlinkOAuth2Account(loginUser.getUsername());

        //OAuth 인증 서버에 연동해제 요청
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(oAuth2AccountDTO.getProvider());
        OAuth2Service oAuth2Service = OAuth2ServiceFactory.getOAuth2Service(restTemplate, oAuth2AccountDTO.getProvider());
        oAuth2Service.unlink(clientRegistration, oAuth2AccountDTO.getOAuth2Token());
    }
```



```java
    @Override
    public OAuth2AccountDTO unlinkOAuth2Account(String username) {
        User user = checkRegisteredUser(username);

        //연관관계 해제
        OAuth2Account oAuth2Account = user.getSocial();
        OAuth2AccountDTO oAuth2AccountDTO = oAuth2Account.toDTO();
        user.unlinkSocial();
        oAuth2AccountRepository.delete(oAuth2Account);

        return oAuth2AccountDTO;
    }
```



```java
public class User extends BaseEntity {

  	...
      
    public void linkSocial(OAuth2Account oAuth2Account) {
        Assert.state(social == null, "하나의 소셜 서비스만 연동할 수 있습니다.");
        this.social = oAuth2Account;
        oAuth2Account.linkUser(this);
    }

    public void unlinkSocial() {
        Assert.state(type.equals(UserType.DEFAULT), "소셜 계정으로 가입된 계정은 연동 해제가 불가능합니다.");
        Assert.state(social != null, "연동된 소셜 계정 정보가 없습니다.");
        this.social.unlinkUser();
        this.social = null;
    }
}
```



```java
public class OAuth2Account extends BaseEntity {

  	... 
      
    public void linkUser(User user) {
        Assert.state(this.user == null, "소셜 계정에 연동 된 다른 계정이 존재합니다.");
        this.user = user;
    }
  
    public void unlinkUser() {
        Assert.state(this.user != null, "연동 된 계정이 존재하지 않습니다.");
        this.user = null;
    }

}
```





