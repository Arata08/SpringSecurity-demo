package com.example.controller;

import com.example.pojo.ResponseResult;
import com.example.pojo.User;
import com.example.service.LoginService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author 陈兴
 * @Create 2024-11-05-下午3:24
 * @Description：
 */
@RestController()
@RequestMapping("user")
public class LoginController {
    @Autowired
    LoginService loginService;

    @PostMapping("login")
    public ResponseResult login(@RequestBody User user){
        return loginService.login(user);
    }

    @PostMapping("logout")
    public ResponseResult logout(){
        return loginService.logout();
    }

    @PostMapping("test")
    public ResponseResult test(){
        return new ResponseResult<>(200,"success",null);
    }

    @PostMapping("register")
    public ResponseResult registerUser(@RequestBody User user){
        return loginService.register(user);
    }
}
