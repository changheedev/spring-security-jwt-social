# 회원가입

### User 엔티티 구현

---



**BaseEntity**

엔티티 클래스에서 공통으로 사용되는 컬럼을 관리하기 위한 abstract 클래스 입니다.

다른 엔티티 클래스들은 BaseEntity 클래스를 상속받게 됩니다.

```java
@MappedSuperclass
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
//for @CreatedDate, @LastModifiedDate
@EntityListeners(value = { AuditingEntityListener.class }) 
public abstract class BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="CREATE_AT", nullable = false, updatable = false)
    @CreatedDate
    private LocalDateTime createAt;

    @Column(name="UPDATE_AT", nullable = false)
    @LastModifiedDate
    private LocalDateTime updateAt;
}
```



**UserType**

기본 회원가입을 통해 가입한 계정과 소셜 로그인을 통해 가입한 계정을 구분하기 위한 enum 클래스 입니다.

```java
public enum UserType {
    DEFAULT, OAUTH
}
```



**AuthorityType**

회원의 권한을 구분하기 위한 enum 클래스 입니다.

```java
public enum AuthorityType {
    ROLE_ADMIN, ROLE_MEMBER
}
```



**User**

회원 테이블과 매핑되는 User 엔티티 클래스 입니다.

```java
@Entity
@Getter
@Table(name = "TBL_USER")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {

    @Column(nullable = false, length = 20)
    private String name;

    @Column(unique = true)
    private String email;

    @Column(nullable = false, unique = true)
    private String username;

    private String password;

    @Enumerated(value = EnumType.STRING)
    private UserType type;

    @ElementCollection(targetClass = AuthorityType.class)
    @CollectionTable(name = "TBL_USER_AUTHORITY", joinColumns = @JoinColumn(name = "USER_ID"))
    @Enumerated(EnumType.STRING)
    private List<AuthorityType> authorities = new ArrayList<>();

    @Builder
    public User(String username, String name, String email, String password, UserType type) {
        this.username = username;
        this.name = name;
        this.email = email;
        this.password = password;
        this.authorities.add(AuthorityType.ROLE_MEMBER);
        this.type = type;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities.stream().map(authority -> new SimpleGrantedAuthority(authority.toString())).collect(Collectors.toList());
    }
}
```



**@ElementCollection**

회원은 기본적으로 **ROLE_MEMBER** 권한을 가지지만 추가적으로 권한을 더 가질 수 있기때문에 List 타입으로 선언했습니다.  그리고 권한 정보의 경우 독자적으로 조회되는 경우는 없기 때문에 별도의 엔티티로 구현하는 대신 **ElementCollection** 으로 처리하였습니다. 



**@Enumerated(EnumType.STRING)**

enum 타입의 컬럼은 기본적으로 index 값으로 저장됩니다. 예를 들면, UserType 이 DEFAULT 인 경우 0, OAUTH 인 경우 1로 저장됩니다. 이런 경우에는 이후 enum 값들이 변경되거나 순서가 바뀌면 DB 에 저장된 모든 값을 다시 수정해주어야 하는 문제가 생깁니다. 그렇기 때문에 enum 타입의 데이터를 String 타입으로 저장하도록 **@Enumerated(EnumType.STRING)** 어노테이션을 사용하였습니다.





### 회원 가입 Service 구현

---



패스워드를 암호화 할 때 Spring Security 에 포함되어 있는 **BCryptPasswordEncoder** 를 사용하기 위해 PasswordEncoder 의 주입시 리턴되는 객체를 BCryptPasswordEncoder 로 설정해주었습니다. BCryptPasswordEncoder 의 경우 같은 패스워드라도 암호화를 할때마다 매번 다른 결과값이 생성되며 단방향 암호화이기 때문에 암호문을 다시 평문으로 복원할 수 없다는 특징이 있습니다.



**SecurityConfigurer**

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {
  	
  	...
    ...
  
  	/*PasswordEncoder를 BCryptPasswordEncoder로 사용하도록 Bean 등록*/
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

```



**UserRepository**

같은 이메일로 가입된 회원이 존재하는지 검사하는 메소드를 추가합니다.

```java
public interface UserRepository extends JpaRepository<User, Long> {
  	boolean existsByEmail(String email);
}

```



**UserService**

```java
@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void saveUser(SignUpRequest signUpRequest){
        checkDuplicateEmail(signUpRequest.getEmail());
        User user = User.builder()
                .username(signUpRequest.getEmail())
                .name(signUpRequest.getName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .type(UserType.DEFAULT)
                .build();

        userRepository.save(user);
    }

    private void checkDuplicateEmail(String email) {
        if(userRepository.existsByEmail(email))
            throw new DuplicateUserException("사용중인 이메일 입니다.", new SimpleFieldError("email", "사용중인 이메일 입니다."));
    }
}
```



유저의 데이터를 저장하기 전에 checkDuplicateEmail() 메소드를 호출해 같은 이메일을 사용하고 있는 다른 유저가 존재하는지  체크합니다. 같은 이메일을 사용하는 유저가 존재할 경우 뒤에 나오는 커스텀 Exception 인 ValidationException 을 상속받는 DuplicateUserException 을 던지게 됩니다.

username 과 email 필드에 똑같이 email 정보를 넣어주는데 username 필드를 별도로 두는 이유는 소셜 로그인 때문입니다. Security 인증에서 인증 결과 정보를 저장하는 Authenticate 객체를 생성할 때 username 값은 필수로 요구 되는데 소셜 로그인에서는 경우에 따라 email 정보가 없을 수 있습니다. 이런 경우에는 email 값을 username 으로 사용하게 되면 username 값이 없기 때문에 인증이 불가능하게 됩니다. 그런데, 소셜 로그인의 경우에는 유저가 username 값을 직접 사용할 일은 없습니다. 이러한 점을 이용하여 일반 회원 가입의 경우에는 username 값으로 email 값을 사용하고  소셜 로그인의 경우에는 별도의 username 값을 생성하여 등록해주기 위해 username 필드를 별도로 사용하였습니다.

패스워드는 PasswordEncoder 를 이용하여 암호화 한뒤 DB에 저장합니다.



### 회원 가입 Controller 구현

---



**SignUpRequest**

SignUpRequest 클래스는 회원 가입 요청시 전달된 데이터를 매핑하는 클래스 입니다.

입력값이 올바르게 입력되었는지 유효성 검사를 위한 어노테이션들이 사용되었습니다.

```java
@Getter
@Setter
public class SignUpRequest {

    @Size(min = 1, max = 20, message = "이름이 입력되지 않았거나 너무 긴 이름입니다.")
    private String name;

    @NotBlank(message = "이메일을 입력해주세요.")
    @Email(message = "이메일 형식이 잘못되었습니다.")
    private String email;

    @Pattern(regexp = "[a-zA-Z!@#$%^&*-_]{6,20}", message = "6~20 길이의 알파벳과 숫자, 특수문자만 사용할 수 있습니다.")
    private String password;

    @Builder
    public SignUpRequest(String name, String email, String password) {
        this.name = name;
        this.email = email;
        this.password = password;
    }
}
```



**UserController**

UserController 에서 @Valid 어노테이션을 사용하면 데이터를 매핑할 때 유효성 검사를 하게 되는데, BindingResult 객체를 이용해 정보를 확인할 수 있습니다. 

```java
@RestController
@RequiredArgsConstructor
@RequestMapping("/users/**")
public class UserController {

    private final UserService userService;
    private final RestTemplate restTemplate;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @PostMapping("")
    public ResponseEntity<?> signUpNewUser(@RequestBody @Valid SignUpRequest signUpRequest, BindingResult bindingResult){
        if(bindingResult.hasErrors()) throw new ValidationException("회원가입 유효성 검사 실패.", bindingResult.getFieldErrors());
        userService.signUpService(signUpRequest);
        return ResponseEntity.ok("Success");
    }
}
```



**SecurityConfigurer**

회원 가입 API 는 미인증 상태에서 호출되어야 하므로 접근 권한을 anonymous() 로 설정합니다.

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {
  	
  	@Override
    protected void configure(HttpSecurity http) throws Exception {
        http...
                .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .antMatchers(HttpMethod.POST, "/users").anonymous()
          ...
    }
}
```



### Exception 핸들링

---



**ValidationException**

유효성 검사에 실패하는 경우 클라이언트에서 해당 정보를 활용할 수 있도록 에러 정보를 담을 수 있는 커스텀 Exception 클래스를 사용하였습니다.

```java
public class ValidationException extends RuntimeException{

    private List<FieldError> errors = new ArrayList<>();

    public ValidationException() {
    }

    public ValidationException(String message, FieldError fieldError) {
        super(message);
        this.errors.add(fieldError);
    }

    public ValidationException(String message, Throwable cause, FieldError fieldError) {
        super(message, cause);
        this.errors.add(fieldError);
    }

    public ValidationException(String message, List<FieldError> errors) {
        super(message);
        this.errors = errors;
    }

    public ValidationException(String message, Throwable cause, List<FieldError> errors) {
        super(message, cause);
        this.errors = errors;
    }

    public List<FieldError> getErrors(){
        return errors;
    }
}
```



**CommonExceptionAdvice**

유효성 검사에 실패하는 경우 클라이언트에서 해당 정보를 활용할 수 있도록 에러 정보를 담을 수 있는 커스텀 Exception 클래스를 사용하였습니다.

```java
@Slf4j
@ControllerAdvice
@RestController
public class CommonExceptionAdvice {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = {ValidationException.class})
    public ErrorResponse validationExceptionHandler(ValidationException e) {
        log.error(e.getMessage(), e);
        List<FieldError> errors = e.getErrors();
        return new ErrorResponse(400, e.getMessage(), errors);
    }

    ...
    ...

    @Getter
    @NoArgsConstructor
    public static class ErrorResponse {
        private int code;
        private String message;
        private List<FieldError> errors;

        public ErrorResponse(int code, String message) {
            this.code = code;
            this.message = message;
        }

        public ErrorResponse(int code, String message, List<FieldError> errors) {
            this.code = code;
            this.message = message;
            this.errors = errors;
        }
    }
}
```
