# SpringBoot + Security + JWT를 이용한 로그인 구현

### Skill & Tools

---

#### Backend

- Java 8
- Spring boot 2.2.1
- Spring Security 5.2.1
- jjwt
- JPA
- MariaDB



#### Front-end

- Vue.js (Nuxt.js)
- Vuex
- Bootstrap-vue



### 구현 기능 & Docs

---

1. [프로젝트 생성 및 DB 연결 설정](docs/Init.md)
2. [Security 설정](docs/Security.md)
3. [회원가입](docs/Signup.md)
4. [기본 로그인](docs/Login.md)
5. [소셜 로그인 & 계정 연동](docs/Social.md)
6. [연동 해제](docs/Unlink.md)
7. 프로필 변경
8. [회원 탈퇴](docs/Withdraw.md)



### Demo Images

---

#### 로그인 페이지

![loginpage](Readme.assets/loginpage.png)



#### 회원가입

![signup](Readme.assets/signup.png)



#### 회원 가입 유효성 검사

![validation](Readme.assets/validation.png)



#### 일반 계정으로 로그인 한 경우 

일반 계정으로 로그인 한 경우 소셜 서비스 연동 메뉴가 보여집니다.

![after_default_login](Readme.assets/after_default_login.png)



#### 소셜 계정 연동 이후

![afterlink](Readme.assets/afterlink.png)



#### 소셜 계정 연동 해제 후 앱 연결 해제 여부 확인

연동 해제를 요청하면 소셜 서비스에도 연동 해제 요청을 보내게 되므로 같은 소셜 계정으로 다시 연결하는 경우 정보 제공 동의 화면이 보여집니다.

![after_unlink1](Readme.assets/after_unlink1.png)

![after_unlink2](Readme.assets/after_unlink2.png)



#### 소셜 로그인으로 가입한 계정에서 연동 해제를 요청하는 경우

소셜 로그인으로 가입한 계정은 연동을 해제할 경우 다시 계정에 접근할 수 없게 되므로 연동 해제 요청이 거부됩니다.

![unlink_social_account](Readme.assets/unlink_social_account.png)

