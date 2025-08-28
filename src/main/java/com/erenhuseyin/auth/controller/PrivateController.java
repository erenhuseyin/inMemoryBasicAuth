package com.erenhuseyin.auth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/private")
public class PrivateController {

    @GetMapping
    public String privateApi() {
        return "Private API";
    }

    //@PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userRoleApi() {
        return "User role private API";
    }

    //@PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminRoleApi() {
        return "Admin role private API";
    }
}
