package com.example.pojo;

public enum ResultCode {
    OK(200, "请求成功"),
    ERROR(500, "请求失败");

    private Integer code;
    private String message;

    private ResultCode(Integer code, String message) {
        this.code = code;
        this.message = message;
    }

    public Integer getCode() {
        return this.code;
    }

    public String getMessage() {
        return this.message;
    }
}