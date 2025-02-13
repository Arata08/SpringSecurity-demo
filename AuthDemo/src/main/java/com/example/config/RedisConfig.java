package com.example.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionCommands;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

    private static final Logger logger = LoggerFactory.getLogger(RedisConfig.class);

    private RedisTemplate redisTemplate;

    @Autowired
    private void setRedisTemplate(RedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Bean
    @SuppressWarnings(value = { "unchecked", "rawtypes" })
    public RedisTemplate<Object, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        redisTemplate.setConnectionFactory(connectionFactory);

        FastJsonRedisSerializer serializer = new FastJsonRedisSerializer(Object.class);

        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(serializer);
        redisTemplate.setHashKeySerializer(new StringRedisSerializer());
        redisTemplate.setHashValueSerializer(serializer);

        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }

    @PostConstruct
    public void checkRedisConnection() {
        try {
            String result = (String) redisTemplate.execute(RedisConnectionCommands::ping);
            if ("PONG".equals(result)) {
                logger.info("✅ -----------------Redis连接成功---------------");
            } else {
                logger.error("❌ ----------------Redis连接异常，响应: {}", result);
                throw new RuntimeException("Redis连接异常");
            }
        } catch (Exception e) {
            logger.error("❌ --------------Redis连接失败", e);
            throw new RuntimeException("Redis连接失败", e);
        }
    }
}