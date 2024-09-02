package com.example.mutualauth.Utility

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import android.widget.Toast

class MyHostApduService : HostApduService() {

    private val keyGeneratorUtility: KeyGeneratorUtility = KeyGeneratorUtility()
    private var packetsSend: List<ByteArray> = listOf()
    private var packetIndex = 0


    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray {
        try {
            if(commandApdu.contentEquals(Utils.SELECT_APD)){
                // returning response apdu , total data that can be sent is 260 bytes
                Log.d("HostApduService","commandRecieved")

                Toast.makeText(this, "received", Toast.LENGTH_SHORT).show()

                return Utils.concatArrays(Utils.SELECT_OK_SW,Utils.REQUEST_CERTIFICATE)

            }else if (commandApdu.copyOfRange(0, Utils.REQUEST_CERTIFICATE.size).contentEquals(Utils.REQUEST_CERTIFICATE)){
                // adding all the packets received in a single array
                Paired.recievedPackets = Utils.concatArrays(Paired.recievedPackets, commandApdu.copyOfRange(Utils.REQUEST_CERTIFICATE.size, commandApdu.size))
                Log.d("HostApduService",Paired.recievedPackets.toString())
                return Utils.SELECT_OK_SW
            }else if (commandApdu.copyOfRange(0, Utils.FINAL_CERTIFICATE.size).contentEquals(Utils.FINAL_CERTIFICATE)) {
                if (packetsSend.isEmpty()) {
                    packetsSend = Utils.createApduPackets(
                        Utils.x509ToByteArray(keyGeneratorUtility.certificate),
                        254
                    )
                    Paired.generateCertificate()
                    Paired.generatePublicKey()
                    Log.d("certificate", Paired.getCertificate().toString())
                    Log.d("public Key", Paired.getPublicKey().toString())
                }


                return packetsSend[packetIndex++]
            } else if (commandApdu.contentEquals(Utils.RANDOM_EXC)) {
                return Utils.SELECT_OK_SW
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }


        return byteArrayOf(0x00.toByte(), 0x02.toByte())
    }

    override fun onDeactivated(reason: Int) {
        packetIndex = 0
        val intent = Intent(this, MyHostApduService::class.java)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        startService(intent);
    }
}