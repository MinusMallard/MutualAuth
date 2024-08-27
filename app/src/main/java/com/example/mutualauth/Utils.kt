package com.example.mutualauth

import java.util.Arrays

object Utils {

    val OUR_APPLICATION_AID = "F0010203040506"

    val SELECT_APD : ByteArray = byteArrayOf(
        0x00.toByte(),0xA4.toByte(),0x04.toByte(),0x00.toByte(),
        0x06.toByte(),0xF0.toByte(),0x01.toByte(),0x02.toByte(),
        0x03.toByte(),0x04.toByte(),0x05.toByte())

    // "OK" status word sent in response to SELECT AID command (0x9000)
    val SELECT_OK_SW : ByteArray = byteArrayOf(0x90.toByte(), 0x00.toByte())

    val REQUEST_CERTIFICATE: ByteArray = byteArrayOf(0x34.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())

    fun byteArrayToHexString(bytes: ByteArray): String {
        val hexArray = charArrayOf(
            '0',
            '1',
            '2',
            '3',
            '4',
            '5',
            '6',
            '7',
            '8',
            '9',
            'A',
            'B',
            'C',
            'D',
            'E',
            'F'
        )
        val hexChars = CharArray(bytes.size * 2)
        var v: Int
        for (j in bytes.indices) {
            v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v ushr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }

    fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            val highNibble = s[i].digitToIntOrNull(16) ?: 0
            val lowNibble = s[i + 1].digitToIntOrNull(16) ?: 0
            data[i / 2] = ((highNibble shl 4) + lowNibble).toByte()
            i += 2
        }
        return data
    }

    fun concatArrays(first: ByteArray, vararg rest: ByteArray): ByteArray {
        var totalLength = first.size
        for (array in rest) {
            totalLength += array.size
        }
        val result = Arrays.copyOf(first, totalLength)
        var offset = first.size
        for (array in rest) {
            System.arraycopy(array, 0, result, offset, array.size)
            offset += array.size
        }
        return result
    }
}