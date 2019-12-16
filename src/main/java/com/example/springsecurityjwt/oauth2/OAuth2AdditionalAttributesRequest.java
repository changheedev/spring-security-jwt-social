package com.example.springsecurityjwt.oauth2;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuth2AdditionalAttributesRequest {

    private String id;
    private String name;
    private String email;
    private String registrationId;

    @Builder
    public OAuth2AdditionalAttributesRequest(String id, String name, String email, String registrationId) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.registrationId = registrationId;
    }
}
