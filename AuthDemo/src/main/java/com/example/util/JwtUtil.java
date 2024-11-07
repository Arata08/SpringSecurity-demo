package com.example.util;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * JWT工具类
 */
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
     * @return String
     */
    public String createJWT(String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, getUUID()); // 设置过期时间
        return builder.compact();
    }

    private JwtBuilder getJwtBuilder(String subject, Long ttlMillis, String uuid) {
        System.out.println(subject);
        long nowMillis = System.currentTimeMillis();
        if (ttlMillis == null) {
            ttlMillis = jwtTtl;
        }
        long expMillis = nowMillis + ttlMillis;
        Date expDate = new Date(expMillis);
        return Jwts.builder()
                .id(uuid)
                .claim("userId", subject)
                // 设置签名使用的签名算法和签名使用的秘钥
                .signWith(generalKey())
                // 设置过期时间
                .expiration(expDate);
    }

    /**
     * 创建token
     * @param id 唯一标识
     * @param subject token中要存放的数据（json格式）
     * @param ttlMillis token超时时间
     * @return String
     */
    public String createJWT(String id, String subject, Long ttlMillis) {
        JwtBuilder builder = getJwtBuilder(subject, ttlMillis, id); // 设置过期时间
        return builder.compact();
    }

    /**
     * 生成加密后的秘钥 secretKey
     * @return SecretKey
     */
    public SecretKey generalKey() {
        byte[] encodedKey = Base64.getDecoder().decode(jwtKey);
        SecretKey key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "HmacSHA256");
        return key;
    }

    /**
     * Token解密
     *
     *@param token     加密后的token
     * @return Claims
     */
    public Claims parseJWT(String token) {
        //生成 HMAC 密钥，根据提供的字节数组长度选择适当的 HMAC 算法，并返回相应的 SecretKey 对象。

        // 得到DefaultJwtParser
        JwtParser jwtParser = Jwts.parser()
                // 设置签名的秘钥
                .verifyWith(generalKey())
                .build();
        Jws<Claims> jws = jwtParser.parseSignedClaims(token);
        Claims payload = jws.getPayload(); // payload 为一个map对象
        String name = (String)payload.get("userId");
        System.out.println("name = " + name);
        return jws.getPayload();
    }
}