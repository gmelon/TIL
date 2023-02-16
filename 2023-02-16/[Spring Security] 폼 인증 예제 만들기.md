### Principal
* 로그인 유저에 대한 정보를 들고 있다
* Argument Resolver에 의해 `Controller`에서 인자로 사용 가능
  * 로그인 유저가 없으면 null

### security dependency만 추가해도 자동으로 login (인증) 로직이 추가됨
* 자동으로 login, logout 페이지 제공
* 기본 설정 -> 모든 요청은 인증을 필요로 함 (`"/"` 페이지도 로그인을 해야 접근이 가능해짐)
```java
@GetMapping("/")
public String index(Model model, Principal principal) {
  ...
}
```

### WebSecurityConfigurerAdapter 를 상속받아 **인가** 설정 가능
* `HttpSecurity`를 인자로 갖는 `configure()` 메소드를 상속받아 구현 가능
* `mvcMatchers(매칭될 url)`
  * 매칭 url에는 **ant 패턴** 사용 가능
  * `permitAll()` -> 모든 사용자의 접근을 허용
  * `hasRole(role)` -> role 을 갖는 사용자만 접근을 허용
* `anyRequest()` -> 나머지 모든 url에 대해 권한을 일괄 적용
* `formLogin()` -> formLogin 방식을 사용하겠다 선언
* `httpBasic()` -> httpBasic 규약으로 인증을 사용하겠다 선언
```java
http.authorizeRequests()
              .mvcMatchers("/", "/info", "/account/**").permitAll()
              .mvcMatchers("/admin").hasRole("ADMIN")
              .anyRequest().authenticated();
http.formLogin(); // .and() 로 메서드 체인을 하지 않고 별도로 작성하는 것도 가능함
http.httpBasic(); 
```

### 기본 유저 정보 등록
* 기본적으로 `UserDetailsServiceAutoConfiguration` -> `SecurityProperties` -> `User` 의 정보를 가지고 온다
* 설정 파일로 설정 가능
  * SecurityProperties에 `ConfigurationProperties(prefix = "spring.security")` 설정이 되어 있기 때문에 가능
  * `spring.security.user.name`, ... 등으로 설정
* 이 방식의 당연히 불완전 (유저를 직접 추가해야 하고, 설정 파일 탈취 시 보안 문제)

### AuthenticationManagerBuilder 를 인자로 갖는 `configure()` 메소드를 통해 유저 추가 가능
* `inMemoryAuthentication()`, `jdbc`, 등 다양한 방법을 지원
* password에서 `{noop}` 은 비밀번호 암호화 방식, 반드시 prefix로 적어주어야 함
  * 예제에 사용된 `noop`은 암호화를 하지 않겠다는 의미
* inmemory 방식을 사용하면 매번 사용자 추가 시 마다 넣어줘야 하므로 당연히 다른 방법이 존재 -> **jpa 연동**

### UserDetailsService (interface) 
* 저장소에 들어있는 사용자 정보를 가져올 때 사용되는 interface
* 얘를 상속받고, `loadUserByUsername()` 를 재정의
  * 해당 메서드의 인자인 `username`을 사용해 `유저 정보`를 찾아와서 `UserDetails` (by Spring Security) 를 반환해주면 된다 (`UserDetailsService`의 규약)
  * 그러면 해당 정보를 통해 스프링 시큐리티의 인증 로직이 동작함
* 시큐리티가 제공하는 `User.builder()` 를 사용하면 `UserDetail`를 편하게 생성할 수 있다
* `UserDetailsService` 도 원래는 설정 파일의 `configure()` 내부에서 사용하겠다고 등록해주어야 하지만 빈으로 등록되면 (`@Service`) 스프링 부트가 자동으로 처리해줌

### UserDetailsService 만 등록된 상태에서 바로 실행하면 로그인 불가
* `PasswordEncoder` 부재로 발생
  * 암호화 전략을 지정해줘야 함
  * 즉, password 인코딩 로직 추가 필요

### PasswordEncoder
* PasswordEncoder 빈 등록
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
```
* `PasswordEncoderFactories.createDelegatingPasswordEncoder()` 를 사용하면 `DelegatingPasswordEncoder`를 얻을 수 있고, 이를 통해 암호화 / 복호화가 가능
  * 기본 전략은 `bcrypt`
  * `noop` 사용 시 암호화를 하지 않는다는 의미 (레거시 지원)
```java
@RequiredArgsConstructor
@Service
public class AccountService implements UserDetailsService {
  
  private final PasswordEncoder passwordEncoder;

  ...

  // account 정보를 받아 password를 **인코딩** 한 후 db에 저장
  public Account createNew(Account account) {
      account.encodePassword(passwordEncoder);
      return accountRepository.save(account);
  }

  ...

}
```
* NoOpEncoder를 사용하면 `{noop}`도 사용하지 않는 것. 읽고 쓸 때 모두 비밀번호가 날 것 그대로 저장됨

### 테스트 시 유저 mocking
* `SecurityMockMvcRequestPostProcessors.user()` 를 사용해 user, roles, password 등을 mocking하는게 가능
* `@WithMockUser(username = "gmelon", roles = "ADMIN")` 이나 `@WithAnonymousUser` 으로 어노테이션 기반 mocking 가능..!
  * 어노테이션이 반복되는 경우 커스텀 어노테이션 생성해서 활용하는 것도 가능
### 회원 가입
* `password` 인코딩만 신경써서 알아서 구현하면 된다. 시큐리티가 회원가입에는 그 이상으로 관여하지 않음
### HTTP BASIC 인증
* `header`를 통해 인증하는 표준, 위험한 인증 방식 -> `https`를 사용할 때만 사용해야함

## 질문
### 1. bcrypt 전략
* https://inpa.tistory.com/entry/NODE-%F0%9F%93%9A-bcrypt-%EB%AA%A8%EB%93%88-%EC%9B%90%EB%A6%AC-%EC%82%AC%EC%9A%A9%EB%B2%95#%EC%95%94%ED%98%B8%ED%99%94_%EB%AA%A8%EB%93%88

## 출처
https://www.inflearn.com/course/%EB%B0%B1%EA%B8%B0%EC%84%A0-%EC%8A%A4%ED%94%84%EB%A7%81-%EC%8B%9C%ED%81%90%EB%A6%AC%ED%8B%B0