package com.example.mutualauth

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import com.example.mutualauth.Utils

class MyHostApduService : HostApduService() {


    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        if(commandApdu.contentEquals(Utils.SELECT_APD)){
            // returning response apdu , total data that can be sent is 260 bytes
            Log.d("HostApduService","commandRecieved")

            Toast.makeText(this, "received", Toast.LENGTH_SHORT)
            var ex : ByteArray = byteArrayOf(24,43,43)
            return Utils.concatArrays(Utils.SELECT_OK_SW,ex)
        }else if (commandApdu[0] == 0x34.toByte() && commandApdu[1] == 0x00.toByte() ){
            //
            return byteArrayOf(0x00.toByte(),0x02.toByte())
        }

        return byteArrayOf(0x00.toByte(), 0x02.toByte())
    }

    override fun onDeactivated(reason: Int) {
        TODO("Not yet implemented")
    }
}