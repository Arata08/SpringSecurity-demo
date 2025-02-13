package com.example.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseResult<T> {
    /**
     * 状态码
     */
    private Integer code;
    /**
     * 提示信息，如果有错误时，前端可以获取该字段进行提示
     */
    private String msg;
    /**
     * 查询到的结果数据，
     */
    private T data;

    public ResponseResult(Integer code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    public ResponseResult(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public ResponseResult(Integer code, T data) {
        this.code = code;
        this.data = data;
    }

    public ResponseResult(ResultCode resultCode) {
        this.code = resultCode.getCode();
        this.msg = resultCode.getMessage();
    }

    public ResponseResult(ResultCode resultCode, T data) {
        this.code = resultCode.getCode();
        this.msg = resultCode.getMessage();
        this.data = data;
    }

    public static ResponseResult error() {
        return new ResponseResult(ResultCode.ERROR);
    }

    public static ResponseResult success() {
        return new ResponseResult(ResultCode.OK);
    }
}
