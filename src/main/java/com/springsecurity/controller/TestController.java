package com.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

@RestController
public class TestController {
    @RolesAllowed("ROLE_ADMIN")
    @GetMapping("/users/list")
    public String getUsers(){
        return "users";
    }

    @GetMapping("/users/add")
    public String addUsers(){
        return "users-added";
    }
}
