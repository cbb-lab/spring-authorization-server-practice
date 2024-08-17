package io.authorizationserver.web

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

@Controller
class ViewController {

    @GetMapping
    fun home() = "home"

    @GetMapping("/login")
    fun login() = "login"
}