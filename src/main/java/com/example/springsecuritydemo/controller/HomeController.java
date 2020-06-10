package com.example.springsecuritydemo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collection;

@Controller
public class HomeController {
    @GetMapping("/login")
    public ModelAndView login() {
        ModelAndView mav = new ModelAndView();
        mav.setViewName("custom-login");
        return mav;
    }

    @GetMapping("/secure/man")
    public ModelAndView welcome1(Authentication authentication) {
        ModelAndView mav = new ModelAndView();
        mav.setViewName("info");
        return mav;
    }

    @GetMapping("/secure/dev")
    public ModelAndView welcome2(Authentication authentication) {
        ModelAndView mav = new ModelAndView();
        Authentication authorities = SecurityContextHolder.getContext().getAuthentication();
        mav.setViewName("info");
        return mav;
    }

    @GetMapping("/accessDenied")
    public ModelAndView error() {
        ModelAndView mav = new ModelAndView();
        Authentication authorities = SecurityContextHolder.getContext().getAuthentication();
        String errorMessage = "You are not authorized to access this page.";
        mav.addObject("errorMsg", errorMessage);
        mav.setViewName("access-denied");
        return mav;
    }
}