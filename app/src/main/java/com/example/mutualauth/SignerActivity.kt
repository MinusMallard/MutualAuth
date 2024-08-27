package com.example.mutualauth

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.example.mutualauth.Utility.Utils
import com.example.mutualauth.ui.theme.MutualAuthTheme

class SignerActivity : ComponentActivity(), NfcAdapter.ReaderCallback {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        NfcAdapter.getDefaultAdapter(this).enableReaderMode(
            this,
            this,
            NfcAdapter.FLAG_READER_NFC_A ,
            null
        )
        setContent {
            MutualAuthTheme {
//                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
//
//                }
            }
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun onTagDiscovered(tag: Tag?) {
        val isoDep : IsoDep? = IsoDep.get(tag)

        Log.d("signerActivity", "Tag discovered")
        if(isoDep != null) {
            try {
                isoDep.connect()
                var commandApdu : ByteArray = Utils.SELECT_APD
                var result = isoDep.transceive(commandApdu)
                Log.d("result", result.toHexString())
                if (result[0] == Utils.SELECT_OK_SW[0] && result[1] == Utils.SELECT_OK_SW[1]){
                    Log.d("success", "connected")
                }
                runOnUiThread {
                    Toast.makeText(this, "connected", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    override fun onPause() {
        super.onPause()
        NfcAdapter.getDefaultAdapter(this).disableReaderMode(this)
    }

    override fun onResume() {
        super.onResume()
        NfcAdapter.getDefaultAdapter(this)
            .enableReaderMode(
                this,
                this,
                NfcAdapter.FLAG_READER_NFC_A,
                null)
    }
}

