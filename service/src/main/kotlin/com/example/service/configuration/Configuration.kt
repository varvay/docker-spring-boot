package com.example.service.configuration

import org.springframework.context.annotation.Bean
import org.springframework.web.client.RestTemplate

@org.springframework.context.annotation.Configuration
class Configuration {

    @Bean
    fun restTemplate(): RestTemplate {
        return RestTemplate()
    }

}