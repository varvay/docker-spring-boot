package com.example.enc.model.response

data class PostKeyExchangeResponse(
    val encClientPubKey: String,
    val encClientPrivKey: String,
    val signClientPubKey: String,
    val signClientPrivKey: String,
    val encServerPubKey: String,
    val encServerPrivKey: String,
    val signServerPubKey: String,
    val signServerPrivKey: String,
)