package com.okan.springbootjwt.request;

import lombok.*;

import java.io.Serializable;

@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class JwtRequest implements Serializable {
    @ToString.Exclude
    private static final long serialVersionUID = 5926468583005150707L;

    @Getter @Setter
    private String username;

    @Getter @Setter
    private String password;
}
