package com.example.enc.model.request

data class PostKeyExchangeRequest(val encClientPubKey: String, val encClientPrivKey: String,
                                  val signClientPubKey: String, val signClientPrivKey: String)