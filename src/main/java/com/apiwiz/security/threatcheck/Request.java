package com.apiwiz.security.threatcheck;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.io.Serializable;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class Request implements Serializable {
    private Map<String, Object> queryParams;
    private Map<String, Object> headerParams;
    private Map<String, Object> formParams;
    private Map<String, Object> pathParams;
    private Object requestBody;
    private String path;
    void setVariable(String variable, String variable1) {
        return;
    }

}
