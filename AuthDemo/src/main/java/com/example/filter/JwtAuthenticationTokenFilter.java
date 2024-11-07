package com.example.filter;

import com.example.pojo.LoginUser;
import com.example.util.JwtUtil;
import com.example.util.RedisCache;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationTokenFilter.class);

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            // 1. 获取 token 从 header 中
            String token = request.getHeader("token");
            if (!StringUtils.hasText(token)) {
                // 放行，让后面的过滤器执行
                filterChain.doFilter(request, response);
                return;
            }

            // 2. 解析 token
            String userId;
            try {
                Claims claims = jwtUtil.parseJWT(token);
                userId = (String) claims.get("userId");
            } catch (Exception e) {
                log.info("Token 解析失败: {}", e.getMessage());
                throw new RuntimeException("Token 不合法！");
            }

            // 3. 根据 userId 从 Redis 获取用户信息
            LoginUser loginUser = redisCache.getCacheObject("login:" + userId);
            if (Objects.isNull(loginUser)) {
                log.error("用户 {} 未登录！", userId);
                throw new RuntimeException("当前用户未登录！");
            }

            // 4. 封装 Authentication
            UsernamePasswordAuthenticationToken authenticationToken
                    = new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());

            // 5. 存入 SecurityContextHolder
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            // 放行，让后面的过滤器执行
            filterChain.doFilter(request, response);
        } catch (RuntimeException e) {
            log.error("过滤器处理异常: {}", e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(e.getMessage());
        }
    }
}