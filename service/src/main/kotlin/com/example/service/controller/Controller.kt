package com.example.service.controller

import com.example.service.controller.model.request.PostDecRequest
import com.example.service.controller.model.request.PostEncRequest
import com.example.service.controller.model.response.PostEncResponse
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpEntity
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate

@RestController
class Controller {

    @Autowired
    private lateinit var restTemplate: RestTemplate

    @PostMapping("/enc-trx", produces = ["application/json"])
    fun postEncTrx(@RequestHeader("X-Device-ID") deviceId: String,
                   @RequestBody request: PostDecRequest): PostEncResponse? {
        val host = "http://localhost:8080"

        val headers = HttpHeaders()
        headers.set("X-Device-ID", deviceId)

        val rawRequest = restTemplate.exchange(
            "$host/dec-verify",
            HttpMethod.POST,
            HttpEntity(request, headers),
            String::class.java
        ).body

        return restTemplate.exchange(
            "$host/sign-enc",
            HttpMethod.POST,
            HttpEntity(PostEncRequest(ObjectMapper().writeValueAsString(rawRequest)), headers),
            PostEncResponse::class.java
        ).body
    }

    @PostMapping("/trx", produces = ["application/json"])
    fun postTrx(request: HttpServletRequest): String {
        return request.inputStream.bufferedReader().use { it.readText() }
    }

}