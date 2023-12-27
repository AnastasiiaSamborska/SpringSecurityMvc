package com.samborska_anastasiia.springsecuritymvc.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DemoController {

    @GetMapping("/")
    public String showHome(){
        return "home";
    }

    // Request mapping for /leaders

    @GetMapping("/leaders")
    public String showLeaders(){
        return "leaders";
    }

    // Request mapping for /systems
    @GetMapping("/systems")
    public String showSystems(){
        return "systems";
    }



}