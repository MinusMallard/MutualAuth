package com.example.mutualauth

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.nfc.NfcAdapter
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeContentPadding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat.startActivity
import com.example.mutualauth.Connection.NFC_Utils
import com.example.mutualauth.ui.theme.MutualAuthTheme

class MainActivity : ComponentActivity() {
    @SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val adapter = NfcAdapter.getDefaultAdapter(this)
        if (!NFC_Utils.isNFCEnabled(this)) {
            NFC_Utils.promptEnableNFC(this)
        }

        val intent1 = Intent(this, SignerActivity::class.java)
        val intent2 = Intent(this, SigneeActivity::class.java)
        setContent {
            MutualAuthTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    SelectScreen(
                        modifier = Modifier.safeDrawingPadding(),
                        intent1 = intent1,
                        intent2 = intent2,
                        context = this
                    )
                }
            }
        }
    }
}

@Composable
fun SelectScreen(
    modifier: Modifier = Modifier,
    intent1: Intent,
    intent2: Intent,
    context: Context
) {
    Box(
        modifier = modifier.fillMaxSize()
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()

        ) {
            StateButton(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(8.dp),
                image = R.drawable.untitled_design__3_,
                buttonText = "SIGNEE",
                onClick = {startActivity(context,intent2,null)}
            )
            StateButton(
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .padding(8.dp),
                image = R.drawable.untitled_design__2_,
                buttonText = "SIGNER",
                onClick = {startActivity(context,intent1,null)}
            )
        }
    }
}

@Composable
fun StateButton(
    modifier: Modifier = Modifier,
    image: Int,
    buttonText: String,
    onClick:() -> Unit,
) {
    Button(
        onClick = { onClick() },
        shape = RoundedCornerShape(16.dp),
        modifier = modifier,
        colors = ButtonDefaults.buttonColors(
            containerColor = Color.White
        )

    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Image(
                painter = painterResource(id = image),
                contentDescription = "documents",
                contentScale = ContentScale.Fit,
            )
            Text(
                text = buttonText,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}