package org.telegram.messenger;

import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.TLRPC;
import org.telegram.tgnet.tl.TL_account;

import java.util.ArrayList;
import java.util.Collections;

public class AccountWatchdog {

    private static volatile AccountWatchdog[] Instance = new AccountWatchdog[UserConfig.MAX_ACCOUNT_COUNT];

    public static AccountWatchdog getInstance(int account) {
        AccountWatchdog localInstance = Instance[account];
        if (localInstance == null) {
            synchronized (AccountWatchdog.class) {
                localInstance = Instance[account];
                if (localInstance == null) {
                    Instance[account] = localInstance = new AccountWatchdog(account);
                }
            }
        }
        return localInstance;
    }

    private final int currentAccount;
    private boolean checking;

    private AccountWatchdog(int account) {
        currentAccount = account;
    }

    public void check() {
        if (checking || !UserConfig.getInstance(currentAccount).isClientActivated()) {
            return;
        }
        checking = true;
        TL_account.getAuthorizations req = new TL_account.getAuthorizations();
        ConnectionsManager.getInstance(currentAccount).sendRequest(req, (response, error) -> {
            if (error == null && response instanceof TL_account.authorizations) {
                TL_account.authorizations res = (TL_account.authorizations) response;
                enforceLimits(res.authorizations);
            }
            checking = false;
        });
    }

    private void enforceLimits(ArrayList<TLRPC.TL_authorization> authorizations) {
        if (authorizations == null) return;

        ArrayList<TLRPC.TL_authorization> desktopSessions = new ArrayList<>();
        ArrayList<Long> sessionsToTerminate = new ArrayList<>();

        for (int a = 0, N = authorizations.size(); a < N; a++) {
            TLRPC.TL_authorization auth = authorizations.get(a);
            if (auth.current) {
                continue;
            }

            // Rule 1: Terminate all other official app sessions
            if (auth.official_app) {
                sessionsToTerminate.add(auth.hash);
                continue;
            }

            // Rule 2: Identify Desktop vs Mobile
            String platform = auth.platform != null ? auth.platform.toLowerCase() : "";
            boolean isDesktop = platform.contains("windows") || platform.contains("macos") || platform.contains("linux") || platform.contains("desktop");

            if (isDesktop) {
                desktopSessions.add(auth);
            } else {
                // Rule 3: Terminate all other mobile sessions (current is already skipped)
                sessionsToTerminate.add(auth.hash);
            }
        }

        // Rule 4: Keep only ONE Desktop session (the most recent one)
        if (desktopSessions.size() > 1) {
            Collections.sort(desktopSessions, (a, b) -> Integer.compare(b.date_active, a.date_active));
            for (int i = 1; i < desktopSessions.size(); i++) {
                sessionsToTerminate.add(desktopSessions.get(i).hash);
            }
        }

        for (int i = 0; i < sessionsToTerminate.size(); i++) {
            terminateSession(sessionsToTerminate.get(i));
        }
    }

    private void terminateSession(long hash) {
        TL_account.resetAuthorization req = new TL_account.resetAuthorization();
        req.hash = hash;
        ConnectionsManager.getInstance(currentAccount).sendRequest(req, (response, error) -> {
            if (error == null) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("AccountWatchdog: terminated session " + hash);
                }
            }
        });
    }
}
