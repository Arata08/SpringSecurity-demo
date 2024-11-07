package com.example.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.pojo.User;
import com.example.service.SysUserService;
import com.example.mapper.SysUserMapper;
import org.springframework.stereotype.Service;

/**
* @author ChenXing
* @description 针对表【sys_user(用户表)】的数据库操作Service实现
* @createDate 2024-11-05 14:10:17
*/
@Service
public class SysUserServiceImpl extends ServiceImpl<SysUserMapper, User>
    implements SysUserService{

}




