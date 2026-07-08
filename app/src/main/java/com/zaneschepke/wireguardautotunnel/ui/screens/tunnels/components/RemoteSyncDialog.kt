package com.zaneschepke.wireguardautotunnel.ui.screens.tunnels.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.zaneschepke.wireguardautotunnel.R

/**
 * Non-dismissable progress dialog shown while the first-launch remote-server
 * sync is in flight. The dialog closes itself the moment the sync flow
 * completes (the `isRemoteSyncing` StateFlow flips to false in the
 * bootstrap coordinator). The user cannot tap-out of it because closing
 * would leave the in-flight import without UI feedback.
 */
@Composable
fun RemoteSyncDialog(onCancel: (() -> Unit)? = null) {
    AlertDialog(
        onDismissRequest = { /* no-op; sync is mandatory on first launch */ },
        title = {
            Text(text = stringResource(R.string.morty_sync_dialog_title))
        },
        text = {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Start,
            ) {
                CircularProgressIndicator(modifier = Modifier.size(28.dp))
                Spacer(modifier = Modifier.width(20.dp))
                Text(text = stringResource(R.string.morty_sync_dialog_message))
            }
        },
        confirmButton = {
            if (onCancel != null) {
                TextButton(onClick = onCancel) {
                    Text(text = stringResource(R.string.cancel))
                }
            }
        },
    )
}
