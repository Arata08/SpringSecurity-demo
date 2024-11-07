package com.example.service;

import com.example.pojo.ResponseResult;
import com.example.pojo.User;

/**
 * @Author 陈兴
 * @Create 2024-11-05-下午3:25
 * @Description：
 */
public interface LoginService {
    ResponseResult login(User user);

    ResponseResult logout();

    ResponseResult register(User user);
}
