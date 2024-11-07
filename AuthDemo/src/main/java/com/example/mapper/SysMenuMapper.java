package com.example.mapper;

import com.example.pojo.SysMenu;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

import java.util.List;

/**
* @author ChenXing
* @description 针对表【sys_menu(菜单表)】的数据库操作Mapper
* @createDate 2024-11-07 14:10:33
* @Entity com.example.pojo.SysMenu
*/
public interface SysMenuMapper extends BaseMapper<SysMenu> {

    List<String> selectPermsByUserId(Long userId);

}




