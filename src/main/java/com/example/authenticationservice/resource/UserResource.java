package com.example.authenticationservice.resource;

import javax.servlet.http.HttpServletResponse;

import com.example.authenticationservice.domain.AuthenticationTokenImpl;
import com.example.authenticationservice.service.RedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserResource {

    @Autowired
    private RedisService service;

    @RequestMapping(method = RequestMethod.GET, value = "/")
    public String getName(AuthenticationTokenImpl auth, HttpServletResponse response) {
        return auth.getPrincipal().toString();
    }

    @RequestMapping(value = "/processor", method = RequestMethod.GET)
    public Integer getProcessor(AuthenticationTokenImpl auth, HttpServletResponse response) {
        return Runtime.getRuntime().availableProcessors();
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public String logout(AuthenticationTokenImpl auth, HttpServletResponse response) {
        service.setValue(auth.getPrincipal().toString().toLowerCase(), "");
        return "Logout Successfully";
    }
}
