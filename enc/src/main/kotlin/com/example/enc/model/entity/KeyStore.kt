package com.example.enc.model.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import lombok.NoArgsConstructor

@Entity
@NoArgsConstructor
class KeyStore(

    @Id
    @Column(name = "device_id", nullable = false)
    val deviceId: String,

    @Column(name = "enc_client_pub_key", nullable = false)
    val encClientPubKey: String,

    @Column(name = "enc_client_priv_key", nullable = false)
    val encClientPrivKey: String,

    @Column(name = "sign_client_pub_key", nullable = false)
    val signClientPubKey: String,

    @Column(name = "sign_client_priv_key", nullable = false)
    val signClientPrivKey: String,

    @Column(name = "enc_server_pub_key", nullable = false)
    val encServerPubKey: String,

    @Column(name = "enc_server_priv_key", nullable = false)
    val encServerPrivKey: String,

    @Column(name = "sign_server_pub_key", nullable = false)
    val signServerPubKey: String,

    @Column(name = "sign_server_priv_key", nullable = false)
    val signServerPrivKey: String,

)