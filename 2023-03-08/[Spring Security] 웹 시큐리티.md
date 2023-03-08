## 스프링 시큐리티 ignoring()

아래와 같이 index 페이지에 css를 적용하고 다시 요청을 해보자.

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="/css/index.css">
    <title>Index</title>
</head>
<body>
    <h1 id="hello" th:text="${message}">Hello</h1>
</body>
</html>
```

```css
#hello {
    font-size: 100px;
}
```

css로 폰트 크기를 변경했음에도 실제로는 반영이 되지 않은 것을 확인할 수 있다.

![image-20230308162509142](./images/ignoring_1.png)

개발자 콘솔로 요청과 응답 상태를 확인해보면, css 파일을 요청하는데 302(리다이렉션) 코드가 뜨고 login 페이지를 추가로 요청한 것을 확인할 수 있다.

![image-20230308163242123](./images/ignoring_2.png)

이는 `WebSecurityConfigurerAdapter`를 통해 시큐리티를 설정할 때 지정한 경로 외의 모든 요청은 인증을 받도록 했기 때문에 정적 리소스를 요청하는 경로 또한 인증을 필요로 하게 되었기 때문에 발생하는 문제이다. 이를 해결하기 위해서는 시큐리티 필터가 적용되지 않도록 ignoring 설정을 해주어야 한다.

`@Configuration` 어노테이션으로 지정된 클래스에 아래와 같이 `WebSecurity`를 인자로 받는 메서드를 추가로 재정의해준다.

```java
@Override
public void configure(WebSecurity web) throws Exception {
    web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
}
```

`ignoring().requestMatchers()` 에 `RequestMatcher`를 인자로 넣어주면 해당 경로의 요청은 시큐리티 필터 수행이 무시된다. 스프링 부트에서 제공하는 `PathRequest` 클래스는 손쉽게 일반적인 정적리소스 경로에 대해 `RequestMatcher`를 리스트로 불러와 사용할 수 있도록 메서드를 제공한다. `toStaticResources().atCommonLocation()`는 아래 경로를 `RequestMatcher`로 만들고 리스트로 반환한다.

```java
CSS("/css/**"),
JAVA_SCRIPT("/js/**"),
IMAGES("/images/**"),
WEB_JARS("/webjars/**"),
FAVICON("/favicon.*", "/*/icon-*");
```

ignoring 설정을 추가하고 다시 요청을 보내보면 아래와 같이 css 파일이 리다이렉션 없이 제대로 응답되고 html에 반영도 잘 되는 것을 확인할 수 있다. `ignoring()` 에는 `requestMatchers()`는 물론 `mvcMatchers()` 등 여러 가지 방법으로 자원을 지정하고 해제할 수 있다.

![image-20230308163825077](./images/ignoring_3.png)

추가로 기존 요청들에 대한 설정과 동일하게 아래와 같이 설정해도 리다이렉션 없이 제대로 css 파일을 불러와 적용할 수 있긴 하지만,

```java
http.authorizeRequests()
    ...
	.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
    ...
```

위와 같이 하게되면 (ignoring을 사용할 때와 달리) 시큐리티 필터를 아예 타지 않는게 아니라 필터를 타되, 마지막 인가 필터 (FilterSecurityInterceptor) 에서 **익명 사용자라도 permitAll() 이므로 허용!** 하고 인가를 해주는 방식이 적용되기 때문에 불필요하게 요청에 많은 리소스가 사용된다.

따라서 아예 시큐리티를 적용하지 않을 자원이라면 `ignoring()`을 사용하는게 효율적이라고 할 수 있다.

## WebAsyncManagerIntegrationFilter

`WebAsyncManagerIntegrationFilter` 는 시큐리티 필터 중 가장 먼저 실행되는 필터로 스프링 MVC의 Async 기능을 사용할 때도 (다른 Thread에서도) SecurityContext를 공유하도록 도와준다.

아래와 같이 컨트롤러에서 `Callable`을 반환할 수 있는데, 이때 `Callable` 의 로직은 별도 쓰레드에서 실행된다. `SecurityContext`는 ThreadLocal에 저장되기 때문에 원래대로라면 공유되지 않아야 하지만, WebAsyncManagerIntegrationFilter 가 pre/postProcess를 통해 SecurityContext를 설정/해제해줌으로써 최초 요청 쓰레드와 별개의 쓰레드에서도 SecurityContext의 참조가 가능해진다.

```java
@GetMapping("/async")
@ResponseBody
public Callable<String> async() {
    // 최초 요청 쓰레드
    System.out.println("MVC");
    System.out.println(SecurityContextHolder.getContext().getAuthentication());
    return () -> {
        // 별도 쓰레드
        System.out.println("Callable");
        System.out.println(SecurityContextHolder.getContext().getAuthentication());
        return "ok";
    };
}
```

접속해보면 아래처럼 동일한 Authentication이 조회되는걸 확인할 수 있다.

![image-20230308171802591](./images/async_1.png)

## HeaderWriterFilter

응답 헤더에 시큐리티 관련 헤더를 추가해주는 필터이다. 아래와 같이 보안을 위한 헤더들을 추가해준다. 각 헤더 별로 간단하게 아래와 같은 의미가 있다.

*   Cache-Control, Expires, Pragma : 캐시 히스토리 취약점 방어
*   X-Content-Type-Options : 마임 타입 스니핑 방어
*   X-Frame-Options : clickjacking 방어
*   X-XSS-Protection : 브라우저에 적용된 XSS 필터를 적용해줌

![image-20230308175530078](./images/header_writer_filter.png)

## CsrfFilter





























