package com.example.enc.model.request

data class PostDecVerifyRequest(val nonce: String, val ciphertext: String)