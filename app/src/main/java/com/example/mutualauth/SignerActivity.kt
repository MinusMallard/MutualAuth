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
import androidx.compose.runtime.key
import com.example.mutualauth.Utility.KeyGeneratorUtility
import com.example.mutualauth.Utility.Paired
import com.example.mutualauth.Utility.Utils
import com.example.mutualauth.ui.theme.MutualAuthTheme
import java.util.Arrays

class SignerActivity : ComponentActivity(), NfcAdapter.ReaderCallback {

    // instance of KeyGenerator class
    private val keyGeneratorUtility = KeyGeneratorUtility()

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
                // attempting connection
                isoDep.connect()

                // sending SELECT AID command
                var commandApdu : ByteArray = Utils.SELECT_APD

                // first result with ok_sw
                //-----------------STEP-1---------------------
                var result = isoDep.transceive(commandApdu)
                //--------------------------------------------

                //Log.d("result", result.toHexString())

                // receiving result and checking for ok_sw
                if (result[0] == Utils.SELECT_OK_SW[0] && result[1] == Utils.SELECT_OK_SW[1]){

                    // getting certificate from the keyGeneratorUtility class and converting it to ByteArray
                    val certByteArray = Utils.x509ToByteArray(keyGeneratorUtility.certificate)!!

                    // generating packets of the certificate
                    val packets = Utils.createApduPackets(certByteArray, 255)
                    Log.d("packets", packets.toString())
                    // from here on sending packets to the signee
                    result = isoDep.transceive(packets[0])

                    if (result.contentEquals(Utils.SELECT_OK_SW)) {
                        result = isoDep.transceive(packets[1])
                        if (result.contentEquals(Utils.SELECT_OK_SW)) {
                            result = isoDep.transceive(packets[2])
                            if (result.contentEquals(Utils.SELECT_OK_SW)) {
                                result = isoDep.transceive(Utils.FINAL_CERTIFICATE)
                                if (result.contentEquals(Utils.SELECT_OK_SW)) {
                                    runOnUiThread {
                                        Toast.makeText(this, "certificate sent", Toast.LENGTH_SHORT).show()
                                    }
                                }
                            }
                        }
                    }
                }
                runOnUiThread {
                    Toast.makeText(this, "connected", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                e.printStackTrace()
            } finally {
                isoDep.close()
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

