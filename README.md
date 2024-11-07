推荐查看语雀文档：https://www.yuque.com/cxuser/hswzeb/qhbmcb03s3s6fubv

数据库chen密码为123456

demo模块为SpringSecurity的基本实现，可使用控制台输出的密码登录访问

AuthDemo实现了登录和权限认证

## <font style="color:rgb(44, 62, 80);">web登陆流程</font>

![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730712627825-b4ca40c7-efe5-4884-862f-8b7551112142.png)

### 缺点：
1. <font style="color:rgb(44, 62, 80);">用户使用的是security给的用户名和密码。 想真实地去数据库里，tb_user获取真实的用户名和密码。</font>
2. <font style="color:rgb(44, 62, 80);">security自带的cookie\session模式。 但我们想使用jwt，无状态登陆。</font>
3. <font style="color:rgb(44, 62, 80);">没有实现鉴权操作</font>

## <font style="color:rgb(44, 62, 80);">分析</font>
### <font style="color:rgb(44, 62, 80);">Springsecurity 登陆流程</font>
<font style="color:rgb(44, 62, 80);">springsecurity就是一个过滤器链，内置了关于springsecurity的16的过滤器。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730712927853-c366cb19-3134-4527-b9d1-e1d69e2f72a9.png)

<font style="color:rgb(44, 62, 80);">image-20220820193848980</font>

+ **<font style="color:rgb(44, 62, 80);">UsernamePasswordAuthenticationFilter</font>**<font style="color:rgb(44, 62, 80);">：处理我们登陆页面输入的用户名和密码是否正确的过滤器。</font>
+ **<font style="color:rgb(44, 62, 80);">ExceptionTranslationFilter</font>**<font style="color:rgb(44, 62, 80);">：处理前面的几个过滤器中，有了问题，抛出错误，不让用户登录。</font>
+ **<font style="color:rgb(44, 62, 80);">FilterSecurityInterceptor</font>**<font style="color:rgb(44, 62, 80);">：经行一个权限校验的拦截器。</font>

**<font style="color:rgb(44, 62, 80);">有关security的过滤器链：</font>**![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730712989266-9a0dc980-9c5c-404d-bdc6-ec3049290140.png)

![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730713029823-b59ae15c-287d-4493-95c3-15f07fcfa94d.png)

---

保存于2024年11月4日17:52:22

---

### <font style="color:rgb(44, 62, 80);">自定义登录</font>
![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730713175377-aa4f973b-8062-44e8-85c8-f603f6646b9e.png)

#### <font style="color:rgb(44, 62, 80);">什么是jwt</font>
<font style="color:rgb(44, 62, 80);">JSON Web Token（JWT）存在客户端，</font><font style="color:rgb(17, 17, 17);">客户端每次与服务器通信，都要带上这个 JWT。你可以把它放在 Cookie 里面自动发送，但是这样不能跨域，所以更好的做法是放在 HTTP 请求的头信息</font>`<font style="color:rgb(17, 17, 17);">Authorization</font>`<font style="color:rgb(17, 17, 17);">字段里面。</font>

<font style="color:rgb(44, 62, 80);">特点：可以被看到，但是不能篡改，因为第三部分用了秘钥。</font>

**<font style="color:rgb(44, 62, 80);">一个JWT实际上就是一个字符串，它由三部分组成，头部、载荷与签名。</font>**

+ <font style="color:rgb(0, 0, 0);">Header</font>**<font style="color:rgb(44, 62, 80);">头部</font>**

<font style="color:rgb(17, 17, 17);">Header 部分是一个 JSON 对象，描述 JWT 的元数据，通常是下面的样子。</font>

```javascript
{
  "alg": "HS256",
  "typ": "JWT"
}
```

<font style="color:rgb(17, 17, 17);">上面代码中，</font>`alg`<font style="color:rgb(17, 17, 17);">属性表示签名的算法（algorithm），默认是 HMAC SHA256（写成 HS256）；</font>`typ`<font style="color:rgb(17, 17, 17);">属性表示这个令牌（token）的类型（type），JWT 令牌统一写为</font>`JWT`<font style="color:rgb(17, 17, 17);">。</font>

<font style="color:rgb(17, 17, 17);">最后，将上面的 JSON 对象使用 Base64URL 算法（详见后文）转成字符串。</font>

+ <font style="color:rgb(0, 0, 0);">3.2 Payload</font>**<font style="color:rgb(44, 62, 80);">载荷</font>**

<font style="color:rgb(17, 17, 17);">Payload 部分也是一个 JSON 对象，用来存放实际需要传递的数据。JWT 规定了7个官方字段，供选用。</font>

+ <font style="color:rgb(17, 17, 17);">iss (issuer)：签发人</font>
+ <font style="color:rgb(17, 17, 17);">exp (expiration time)：过期时间</font>
+ <font style="color:rgb(17, 17, 17);">sub (subject)：主题</font>
+ <font style="color:rgb(17, 17, 17);">aud (audience)：受众</font>
+ <font style="color:rgb(17, 17, 17);">nbf (Not Before)：生效时间</font>
+ <font style="color:rgb(17, 17, 17);background-color:rgb(245, 242, 240);">iat (Issued At)：签发时间</font>
+ <font style="color:rgb(17, 17, 17);background-color:rgb(245, 242, 240);">jti (JWT ID)：编号</font>

<font style="color:rgb(17, 17, 17);">除了官方字段，你还可以在这个部分定义私有字段，下面就是一个例子。</font>

```javascript
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```

<font style="color:rgb(17, 17, 17);">注意，JWT 默认是不加密的，任何人都可以读到，所以不要把秘密信息放在这个部分。</font>

<font style="color:rgb(17, 17, 17);">这个 JSON 对象也要使用 Base64URL 算法转成字符串。</font>

+ <font style="color:rgb(0, 0, 0);">3.3 Signature</font>**<font style="color:rgb(44, 62, 80);">签名</font>**

<font style="color:rgb(17, 17, 17);">Signature 部分是对前两部分的签名，防止数据篡改。</font>

<font style="color:rgb(17, 17, 17);">首先，需要指定一个密钥（secret）。这个密钥只有服务器才知道，不能泄露给用户。然后，使用 Header 里面指定的签名算法（默认是 HMAC SHA256），按照下面的公式产生签名。</font>

```java
HMACSHA256(
    base64UrlEncode(header) + "." +
    base64UrlEncode(payload),
    secret)
```

<font style="color:rgb(17, 17, 17);">算出签名以后，把 Header、Payload、Signature 三个部分拼成一个字符串，每个部分之间用"点"（</font>`.`<font style="color:rgb(17, 17, 17);">）分隔，就可以返回给用户。</font>

#### <font style="color:rgb(44, 62, 80);">实现真实从数据库获取系统用户信息</font>
实现UserDetailsService

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名查询用户信息
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUserName,username);
        User user = userMapper.selectOne(wrapper);
        //如果查询不到数据就通过抛出异常来给出提示
        if(Objects.isNull(user)){
            throw new RuntimeException("用户名错误");
        }
        //TODO 根据用户查询权限信息 添加到LoginUser中
        
        
        //封装成UserDetails对象返回 
        return new LoginUser(user);
    }
}
```

```java
/*
该接口实现仅仅存储用户的信息。后续会将该接口提供的用户信息封装到认证对象Authentication中去。
UserDetails 默认提供了：
用户的权限集， 默认需要添加ROLE_ 前缀
用户的加密后的密码， 不加密会使用{noop}前缀
应用内唯一的用户名
账户是否过期
账户是否锁定
凭证是否过期
用户是否可用
还可以自行实现扩展以存储更多的用户信息。比如用户的邮箱、手机号等等。
**/
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements UserDetails {

    private User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
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

#### <font style="color:rgb(44, 62, 80);">自定义一个controller登陆接口</font>
```java
@RestController
public class LoginController {
    @Autowired
    LoginService loginService;

    @PostMapping("/user/login")
    public ResponseResult login(@RequestBody User user){

        return loginService.login(user);
    }

}
```

#### <font style="color:rgb(44, 62, 80);">放行自定义登陆接口</font>
```java
@Configuration
public class SecurityConfig {
    /*
      实际项目中我们不会把密码明文存储在数据库中
      默认使用的PasswordEncoder要求数据库中的密码格式为：{id}password 。它会根据id去判断密码的加密方式。
      但是我们一般不会采用这种方式。
      所以就需要替换PasswordEncoder。
      我们一般使用SpringSecurity为我们提供的BCryptPasswordEncoder。
      我们只需要使用把BCryptPasswordEncoder对象注入Spring容器中，SpringSecurity就会使用该PasswordEncoder来进行密码校验。
    * */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
        // 关闭 CSRF
        .csrf(csrf -> csrf.disable())
        // 不通过 Session 获取 SecurityContext
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorize -> authorize
                               // 对于登录接口 允许匿名访问
                               .requestMatchers("/user/login").permitAll()
                               // 除上面外的所有请求全部需要鉴权认证
                               .anyRequest().authenticated()
                              );

        return http.build();
    }

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
        return authenticationManager;
    }
}
```

#### <font style="color:rgb(44, 62, 80);">使用ProviderManager auth方法进行验证</font>
#### 封装jwt工具类
```java
@Component
public class JwtUtil {

    // 有效期为
    @Value("${com.jwt.user-ttl}")
    public Long jwtTtl;

    // 设置秘钥明文
    @Value("${com.jwt.user-secret-key}")
    public String jwtKey;

    public String getUUID() {
        return UUID.randomUUID().toString().replaceAll("-", "");
    }

    /**
     * 生成JWT
     * @param subject token中要存放的数据（json格式）
     * @return
     */
    public String createJWT(String subject) {
        JwtBuilder builder = getJwtBuilder(subject, null, getUUID()); // 设置过期时间
        return builder.compact();
    }

    /**
     * 生成JWT
     * @param subject token中要存放的数据（json格式）
     * @param ttlMillis token超时时间
     * @return
     */
    public String createJWT(String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, getUUID()); // 设置过期时间
        return builder.compact();
    }

    private JwtBuilder getJwtBuilder(String subject, Long ttlMillis, String uuid) {
        //生成 HMAC 密钥，根据提供的字节数组长度选择适当的 HMAC 算法，并返回相应的 SecretKey 对象。
        SecretKey key = Keys.hmacShaKeyFor(jwtKey.getBytes(StandardCharsets.UTF_8));
        long nowMillis = System.currentTimeMillis();
        if (ttlMillis == null) {
            ttlMillis = jwtTtl;
        }
        long expMillis = nowMillis + ttlMillis;
        Date expDate = new Date(expMillis);
        return Jwts.builder()
        // 设置签名使用的签名算法和签名使用的秘钥
        .signWith(key)
        // 设置过期时间
        .expiration(expDate);
    }

    /**
     * 创建token
     * @param id 唯一标识
     * @param subject token中要存放的数据（json格式）
     * @param ttlMillis token超时时间
     * @return
     */
    public String createJWT(String id, String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, id); // 设置过期时间
        return builder.compact();
    }

    /**
     * 生成加密后的秘钥 secretKey
     * @return
     */
    public SecretKey generalKey() {
        byte[] encodedKey = Base64.getDecoder().decode(jwtKey);
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "HmacSHA256");
        return key;
    }

    /**
     * Token解密
     *
     * @param secretKey jwt秘钥 此秘钥一定要保留好在服务端, 不能暴露出去, 否则sign就可以被伪造, 如果对接多个客户端建议改造成多个
     * @param token     加密后的token
     * @return
     */
    public Claims parseJWT(String secretKey, String token) {
        //生成 HMAC 密钥，根据提供的字节数组长度选择适当的 HMAC 算法，并返回相应的 SecretKey 对象。
        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

        // 得到DefaultJwtParser
        JwtParser jwtParser = Jwts.parser()
        // 设置签名的秘钥
        .verifyWith(key)
        .build();
        Jws<Claims> jws = jwtParser.parseSignedClaims(token);
        Claims claims = jws.getPayload();
        return claims;
    }
}
```

#### <font style="color:rgb(44, 62, 80);">自己生成jwt给前端</font>
#### <font style="color:rgb(44, 62, 80);">系统用户相关所有信息放入redis</font>
```java
@Service
public class LoginServiceImpl implements LoginService {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RedisCache redisCache;

    @Override
    public ResponseResult login(User user) {
        //3使用ProviderManager auth方法进行验证
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user.getUserName(),user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        //校验失败了
        if(Objects.isNull(authenticate)){
            throw new RuntimeException("用户名或密码错误！");
        }

        //4自己生成jwt给前端
        LoginUser loginUser= (LoginUser)(authenticate.getPrincipal());
        String userId = loginUser.getUser().getId().toString();
        String jwt = JwtUtil.createJWT(userId);
        Map<String,String> map=new HashMap();
        map.put("token",jwt);
        //5系统用户相关所有信息放入redis
        redisCache.setCacheObject("login:"+userId,loginUser);

        return new ResponseResult(200,"登陆成功",map);
    }
}
```

### <font style="color:rgb(44, 62, 80);">认证过滤器</font>
#### <font style="color:rgb(44, 62, 80);">获取token</font>
#### <font style="color:rgb(44, 62, 80);">解析token</font>
#### <font style="color:rgb(44, 62, 80);">获取userid</font>
#### <font style="color:rgb(44, 62, 80);">封装Authentication</font>
#### <font style="color:rgb(44, 62, 80);">存入SecurityContextHolder</font>
```java
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    RedisCache redisCache;

    @Autowired
    JwtProperties jwtProperties;

    @Autowired
    JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //1获取token  header的token
        String token = request.getHeader("token");
        if (!StringUtils.hasText(token)) {
            //放行，让后面的过滤器执行
            filterChain.doFilter(request, response);
            return;
        }
        //2解析token
        String userId;
        try {
            Claims claims = jwtUtil.parseJWT(jwtProperties.getUserSecretKey(),token);
            userId = claims.getSubject();
        } catch (Exception e) {
            throw new RuntimeException("token不合法！");
        }

        //3获取userId, redis获取用户信息
        LoginUser loginUser = redisCache.getCacheObject("login:" + userId);
        if (Objects.isNull(loginUser)) {
            throw new RuntimeException("当前用户未登录！");
        }

        //4封装Authentication
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                = new UsernamePasswordAuthenticationToken(loginUser, null, null);

        //5存入SecurityContextHolder
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

        //放行，让后面的过滤器执行
        filterChain.doFilter(request, response);
    }
}
```

#### <font style="color:rgb(44, 62, 80);">6.把token校验过滤器添加到过滤器链中</font>
SecurityConfig中添加：

```java
@Autowired
JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    //把token校验过滤器添加到过滤器链中
    http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
}
```

<font style="color:rgb(44, 62, 80);"></font>

---

保存于2024年11月5日23:36:00

---

## <font style="color:rgb(44, 62, 80);">授权认证</font>
<font style="color:rgb(44, 62, 80);">授权基本流程</font>![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730943113001-08ff9052-04aa-48ae-a23a-22f09bfe8266.png)

<font style="color:rgb(44, 62, 80);">在SpringSecurity中，会使用默认的FilterSecurityInterceptor来进行权限校验。</font>

<font style="color:rgb(44, 62, 80);">在FilterSecurityInterceptor中会从SecurityContextHolder获取其中的Authentication，然后获取其中的权限信息。当前用户是否拥有访问当前资源所需的权限。</font>

<font style="color:rgb(44, 62, 80);">所以我们需要做两步</font>

+ <font style="color:rgb(44, 62, 80);">UserDetailServiceImpl的loadUserByUsername 查询权限信息</font>

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private SysUserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名查询用户信息
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUserName,username);
        User user = userMapper.selectOne(wrapper);
        //如果查询不到数据就通过抛出异常来给出提示
        if(Objects.isNull(user)){
            throw new RuntimeException("用户名错误");
        }
        //TODO 根据用户查询权限信息 添加到LoginUser中


        //封装成UserDetails对象返回
        return new LoginUser(user);
    }
}
```

+ <font style="color:rgb(44, 62, 80);">JwtAuthenticationTokenFilter中放入权限信息loginUser.getAuthorities()</font>

```java
// 4. 封装 Authentication
UsernamePasswordAuthenticationToken authenticationToken
= new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());
```

### <font style="color:rgb(44, 62, 80);">授权实现</font>
#### <font style="color:rgb(44, 62, 80);">限制访问资源所需权限</font>
<font style="color:rgb(44, 62, 80);">SpringSecurity为我们提供了基于注解的权限控制方案，这也是我们项目中主要采用的方式。</font>

<font style="color:rgb(44, 62, 80);">我们可以使用注解去指定访问对应的资源所需的权限。</font>

<font style="color:rgb(44, 62, 80);">但是要使用它我们需要先开启相关配置。配置类中。</font>

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
```

<font style="color:rgb(44, 62, 80);">然后就可以使用对应的注解。@PreAuthorize</font>

```java
@RestController
@RequestMapping("demo")
public class DemoController {

    @GetMapping("hello")
    @PreAuthorize("hasAuthority('sayhello')")
    public String hello(){
        return "hello security.ydlclass666";
    }
}
```

#### <font style="color:rgb(44, 62, 80);">从数据库查询权限信息</font>
##### <font style="color:rgb(44, 62, 80);">RBAC权限模型</font>
<font style="color:rgb(44, 62, 80);">RBAC权限模型（Role-Based Access Control）即：基于角色的权限控制。这是目前最常被开发者使用也是相对易用、通用权限模型。</font>

![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730957932158-ee14e8cd-6bf7-46da-9254-1c4cfa49ffe9.png)

##### 添加sys_menu实体类
```java
@TableName(value="sys_menu")
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Menu implements Serializable {
    private static final long serialVersionUID = 1L;
    
    @TableId
    private Long id;
    /**
    * 菜单名
    */
    private String menuName;
    /**
    * 路由地址
    */
    private String path;
    /**
    * 组件路径
    */
    private String component;
    /**
    * 菜单状态（0显示 1隐藏）
    */
    private String visible;
    /**
    * 菜单状态（0正常 1停用）
    */
    private String status;
    /**
    * 权限标识
    */
    private String perms;
    /**
    * 菜单图标
    */
    private String icon;
    
    private Long createBy;
    
    private Date createTime;
    
    private Long updateBy;
    
    private Date updateTime;
    /**
    * 是否删除（0未删除 1已删除）
    */
    private Integer delFlag;
    /**
    * 备注
    */
    private String remark;
}
```

##### 实现根据用户id查询用户权限列表
```java
public interface SysMenuMapper extends BaseMapper<SysMenu> {

    List<String> selectPermsByUserId(Long userId);

}
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper
PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
"http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.mapper.SysMenuMapper">

  <resultMap id="BaseResultMap" type="com.example.pojo.SysMenu">
    <id property="id" column="id" jdbcType="BIGINT"/>
    <result property="menuName" column="menu_name" jdbcType="VARCHAR"/>
    <result property="path" column="path" jdbcType="VARCHAR"/>
    <result property="component" column="component" jdbcType="VARCHAR"/>
    <result property="visible" column="visible" jdbcType="CHAR"/>
    <result property="status" column="status" jdbcType="CHAR"/>
    <result property="perms" column="perms" jdbcType="VARCHAR"/>
    <result property="icon" column="icon" jdbcType="VARCHAR"/>
    <result property="createBy" column="create_by" jdbcType="BIGINT"/>
    <result property="createTime" column="create_time" jdbcType="TIMESTAMP"/>
    <result property="updateBy" column="update_by" jdbcType="BIGINT"/>
    <result property="updateTime" column="update_time" jdbcType="TIMESTAMP"/>
    <result property="delFlag" column="del_flag" jdbcType="INTEGER"/>
    <result property="remark" column="remark" jdbcType="VARCHAR"/>
  </resultMap>

  <sql id="Base_Column_List">
    id,menu_name,path,
    component,visible,status,
    perms,icon,create_by,
    create_time,update_by,update_time,
    del_flag,remark
  </sql>

  <select id="selectPermsByUserId" parameterType="long" resultType="string">
    SELECT DISTINCT perms from sys_menu where id in (
    SELECT menu_id  from sys_role_menu where role_id in (
    SELECT role_id from sys_user_role  where user_id=#{userId}
    )
    ) and status='0'
  </select>
</mapper>
```

#### <font style="color:rgb(44, 62, 80);">封装权限信息</font>
<font style="color:rgb(44, 62, 80);">我们前面在写UserDetailsServiceImpl的时候说过，在查询出用户后还要获取对应的权限信息，封装到UserDetails中返回。</font>

<font style="color:rgb(44, 62, 80);">我们先直接把权限信息写死封装到UserDetails中进行测试。</font>

<font style="color:rgb(44, 62, 80);">我们之前定义了UserDetails的实现类LoginUser，想要让其能封装权限信息就要对其进行修改。</font>

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements UserDetails {

    private User user;

    List<String> permissions;

    public LoginUser(User user, List<String> permissions) {
        this.user = user;
        this.permissions = permissions;
    }

    @JSONField(serialize = false)
    List<SimpleGrantedAuthority> authorities;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (authorities!=null){
            return authorities;
        }

        authorities = permissions.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
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

<font style="color:rgb(44, 62, 80);">LoginUser修改完后我们就可以在UserDetailsServiceImpl中去把权限信息封装到LoginUser中了。从数据库中查询权限信息。</font>

```java
@Service
public class UserDetailServiceImpl implements UserDetailsService {
    @Autowired
    UserMapper userMapper;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //1根据用户名获取数据库中的系统用户
        LambdaQueryWrapper<User> lambdaQueryWrapper=new LambdaQueryWrapper<>();
        lambdaQueryWrapper.eq(User::getUserName,username); //查询条件
        User user = userMapper.selectOne(lambdaQueryWrapper);
        if(Objects.isNull(user)){
            throw new RuntimeException("用户名错误！");
        }
        
        List<String> perms = SysMenuMapper.selectPermsByUserId(user.getId());

        //3返回UserDetails
        return new LoginUser(user,list);
    }
}
```

<font style="color:rgb(44, 62, 80);">测试：</font>

<font style="color:rgb(44, 62, 80);">已经登录，带上权限了</font>

![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730943576229-749823a1-99d3-4642-a0d2-724ae25d2e74.png)

<font style="color:rgb(44, 62, 80);">image-20220822043131659</font>

<font style="color:rgb(44, 62, 80);">即使登陆成功，也不能访问</font>

![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730943576877-a4daad84-d1fb-4cd6-a979-7dbabf8b19bc.png)

### 额外-<font style="color:rgb(44, 62, 80);">基于配置的权限控制</font>
<font style="color:rgb(44, 62, 80);">在配置类中使用使用配置的方式对资源进行权限控制。</font>

```java
//说明这个方法需要有sayhello这个权限
.antMatchers("/demo/hello").hasAuthority("sayhello")
```

再回顾Controller层注解方法

```java
@RestController
@RequestMapping("demo")
public class DemoController {

    @GetMapping("hello")
    //说明这个方法需要有sayhello这个权限
    @PreAuthorize("hasAuthority('sayhello')")
    public String hello(){
        return "hello security666";
    }
}
```

## <font style="color:rgb(44, 62, 80);">自定义失败处理</font>
<font style="color:rgb(44, 62, 80);">登录认证或者权限认证失败时，现在返回一个错误，不友好。我们想也让他返回我们自定义的返回值实体类@ControllerAdvise</font>

![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730961207196-03c612d4-f2d8-4a79-869b-7ebd678c945d.png)

+ <font style="color:rgb(44, 62, 80);">认证失败：它会封装AuthenticationException，然后调用</font>**<font style="color:rgb(44, 62, 80);">AuthenticationEntryPoint</font>**<font style="color:rgb(44, 62, 80);">的commence方法处理</font>
+ <font style="color:rgb(44, 62, 80);">授权失败：它会封装AccessDeniedException，然后调用</font>**<font style="color:rgb(44, 62, 80);">AccessDeniedHandler</font>**<font style="color:rgb(44, 62, 80);">的handle方法处理</font>

<font style="color:rgb(44, 62, 80);">自定义这两个类的异常处理机制的实现类，配置到SpringSecurity。</font>

### <font style="color:rgb(44, 62, 80);">自定义类处理登陆失败</font>
```java
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        //给前端ResponseResult 的json
        ResponseResult responseResult = new ResponseResult(HttpStatus.UNAUTHORIZED.value(), "登陆认证失败了，请重新登陆！");
        String json = JSON.toJSONString(responseResult);
        WebUtils.renderString(response,json);
    }
}
```

<font style="color:rgb(44, 62, 80);">也可以直接在</font>LoginServiceImpl中抛出<font style="color:rgb(44, 62, 80);">  
</font><font style="color:rgb(44, 62, 80);"> </font>![](https://cdn.nlark.com/yuque/0/2024/png/47353919/1730962109135-980cd6ab-0a93-4688-9556-31699a9a1891.png)

### <font style="color:rgb(44, 62, 80);">自定义类处理权限认证失败</font>
```plain
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        response.setStatus(403);
        response.setContentType("application/json;charset=UTF-8");
        ResponseResult responseResult = new ResponseResult(HttpStatus.FORBIDDEN.value(), "您权限不足！");
        String json = JSON.toJSONString(responseResult);
        response.getWriter().println(json);
    }
}
```

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;
    /*
      实际项目中我们不会把密码明文存储在数据库中
      默认使用的PasswordEncoder要求数据库中的密码格式为：{id}password 。它会根据id去判断密码的加密方式。
      但是我们一般不会采用这种方式。
      所以就需要替换PasswordEncoder。
      我们一般使用SpringSecurity为我们提供的BCryptPasswordEncoder。
      我们只需要使用把BCryptPasswordEncoder对象注入Spring容器中，SpringSecurity就会使用该PasswordEncoder来进行密码校验。
    * */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
        // 关闭 CSRF
        .csrf(AbstractHttpConfigurer::disable)
        // 不通过 Session 获取 SecurityContext
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorize -> authorize
                               // 对于登录接口 允许匿名访问
                               .requestMatchers("/user/login").permitAll()
                               // 忽略静态资源路径
                               .requestMatchers("/images/**", "/js/**", "/webjars/**").permitAll()
                               // 除上面外的所有请求全部需要鉴权认证
                               .anyRequest().authenticated())
        // 设置自定义的 AccessDeniedHandler处理权限不足异常问题
        .exceptionHandling(exception -> exception
                           .accessDeniedHandler(accessDeniedHandler)
                          );
        //把token校验过滤器添加到过滤器链中
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        return authenticationConfiguration.getAuthenticationManager();
    }
}
```

## <font style="color:rgb(44, 62, 80);">SpringSecurity跨域处理</font>
### <font style="color:rgb(44, 62, 80);">先对SpringBoot配置，运行跨域请求</font>
```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
      // 设置允许跨域的路径
        registry.addMapping("/**")
                // 设置允许跨域请求的域名
                .allowedOriginPatterns("*")
                // 是否允许cookie
                .allowCredentials(true)
                // 设置允许的请求方式
                .allowedMethods("GET", "POST", "DELETE", "PUT")
                // 设置允许的header属性
                .allowedHeaders("*")
                // 跨域允许时间
                .maxAge(3600);
    }
}
```

### <font style="color:rgb(44, 62, 80);">开启SpringSecurity的跨域访问</font>
<font style="color:rgb(44, 62, 80);">由于我们的资源都会收到SpringSecurity的保护，所以想要跨域访问还要让SpringSecurity运行跨域访问。</font>

#### <font style="color:rgb(44, 44, 54);">创建一个 CorsConfigurationSource来配置 CORS：</font>
```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.addAllowedOriginPattern("*");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

### <font style="color:rgb(44, 44, 54);">配置 </font>SecurityFilterChain
```java
@Autowired
CorsConfigurationSource corsConfigurationSource;

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
    // SpringSecurity跨域配置
    .cors(cors -> cors.configurationSource(corsConfigurationSource))
    // 关闭 CSRF
    .csrf(AbstractHttpConfigurer::disable)
    // 不通过 Session 获取 SecurityContext
    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .authorizeHttpRequests(authorize -> authorize
                           // 对于登录接口 允许匿名访问
                           .requestMatchers("/user/login").permitAll()
                           // 忽略静态资源路径
                           .requestMatchers("/images/**", "/js/**", "/webjars/**").permitAll()
                           // 除上面外的所有请求全部需要鉴权认证
                           .anyRequest().authenticated())
    // 设置自定义的 AccessDeniedHandler处理权限不足异常问题
    .exceptionHandling(exception -> exception
                       .accessDeniedHandler(accessDeniedHandler)
                      );
    //把token校验过滤器添加到过滤器链中
    http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

    return http.build();
}
```

### over！

### 现在就可以写前端，写controller层啦，快去实践吧！
