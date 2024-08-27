package com.example.mutualauth

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.example.mutualauth.Utility.MyHostApduService
import com.example.mutualauth.ui.theme.MutualAuthTheme

class SigneeActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        Log.d("SigneeActivity", "onCreate called")
        val intent = Intent(this, MyHostApduService::class.java)
        startService(intent)

        setContent {
            MutualAuthTheme {

            }
        }
    }
}

