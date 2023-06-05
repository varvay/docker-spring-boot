package com.example.enc.repository

import com.example.enc.model.entity.KeyStore
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface KeyStoreRepository : JpaRepository<KeyStore, String> {
}