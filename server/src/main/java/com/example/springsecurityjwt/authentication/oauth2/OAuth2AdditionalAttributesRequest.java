package com.example.springsecurityjwt.authentication.oauth2;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
public class OAuth2AdditionalAttributesRequest {

    private Long tid;
    private Map<String, Object> attributes;

    @Builder
    public OAuth2AdditionalAttributesRequest(Long tid, Map<String, Object> attributes) {
        this.tid = tid;
        this.attributes = attributes;
    }
}
