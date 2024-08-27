package com.example.mutualauth.Connection

import android.content.Context
import android.content.Intent
import android.nfc.NfcAdapter
import android.provider.Settings

object NFC_Utils {

    fun isNFCEnabled(context: Context): Boolean {
        val nfcAdapter = NfcAdapter.getDefaultAdapter(context);
        return nfcAdapter != null && nfcAdapter.isEnabled();
    }

    fun promptEnableNFC(context: Context) {
        val intent = Intent(Settings.ACTION_NFC_SETTINGS)
        context.startActivity(intent)
    }
}