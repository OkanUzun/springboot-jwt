package com.okan.springbootjwt.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;

@ToString
@AllArgsConstructor
public class JwtResponse implements Serializable {
    @ToString.Exclude
    private static final long serialVersionUID = -8091879091924046844L;

    @Getter
    private final String jwtToken;
}