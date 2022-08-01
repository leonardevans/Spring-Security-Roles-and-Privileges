package com.springsecurity.controller;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

@RestController
public class TestController {
    @RolesAllowed({"ROLE_ADMIN", "ROLE_USER"})
    @GetMapping("/users/list")
    public String getUsers(){
        return "users";
    }

    @RolesAllowed("ROLE_ADMIN")
    @GetMapping("/users/add")
    public String addUsers(){
        return "users-added";
    }

    @PreAuthorize("hasAuthority('READ_PRIVILEGE')")
    @GetMapping("/users/read")
    public String readUsers(){
        return "users-read";
    }

    @PreAuthorize("hasAuthority('WRITE_PRIVILEGE')")
    @GetMapping("/users/write")
    public String writeUsers(){
        return "users-written";
    }
}
