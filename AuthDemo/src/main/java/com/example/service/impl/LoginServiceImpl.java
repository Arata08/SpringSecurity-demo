package com.example.service.impl;

import com.example.mapper.SysUserMapper;
import com.example.pojo.LoginUser;
import com.example.pojo.ResponseResult;
import com.example.pojo.ResultCode;
import com.example.pojo.User;
import com.example.service.LoginService;
import com.example.util.JwtUtil;
import com.example.util.RedisCache;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.swing.*;
import java.util.HashMap;
import java.util.Map;

/**
 * @Created by IT李老师
 * 公主号 “元动力课堂”
 * 个人微 itlils
 * 规矩：缺啥补啥  干就完事儿 照猫画虎
 */
@Service
@Log
public class LoginServiceImpl implements LoginService {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RedisCache redisCache;

    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    SysUserMapper SysUserMapper;

    @Override
    public ResponseResult login(User user) {
        try {
            //3使用ProviderManager auth方法进行验证
            // 创建 UsernamePasswordAuthenticationToken 对象
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUserName(),
                    user.getPassword());
            // 进行认证
            Authentication authenticate = authenticationManager.authenticate(token);

            //4 认证成功自己生成jwt给前端
            LoginUser loginUser= (LoginUser)(authenticate.getPrincipal());
            String userId = loginUser.getUser().getId().toString();
            String jwt = jwtUtil.createJWT(userId);
            Map<String,String> map = new HashMap<>();
            map.put("token",jwt);
            //5系统用户相关所有信息放入redis
            redisCache.setCacheObject("login:"+userId,loginUser);

            return new ResponseResult(ResultCode.OK,map);
        } catch (AuthenticationException e) {
            // 处理认证失败的情况
            log.info(user.getUserName() + e.getMessage());
            return new ResponseResult(ResultCode.ERROR, " 登陆失败: " + e.getMessage());
        } catch (Exception e) {
            // 处理其他异常
            log.warning(user.getUserName() + e.getMessage());
            return new ResponseResult(ResultCode.ERROR, " 登陆失败: " + e.getMessage());
        }
    }

    @Override
    public ResponseResult logout() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        Long userId = loginUser.getUser().getId();
        redisCache.deleteObject("login:" + userId);

        return ResponseResult.success();
    }

    @Override
    public ResponseResult register(User user) {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        SysUserMapper.insert(user);
        return ResponseResult.success();
    }
}
