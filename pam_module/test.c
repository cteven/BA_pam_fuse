#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <security/pam_ext.h>

static struct pam_conv conv = {
    misc_conv,  // Verwendet die Standard-Konversationsfunktion misc_conv
    NULL
};

int main(int argc, char *argv[]) {
    pam_handle_t *pamh = NULL;
    int retval;
    const char *user = "nobody";  // Standardbenutzer, falls kein Benutzername angegeben ist
    const char *authtok = NULL;

    if(argc == 2) {
        user = argv[1];
    }

    retval = pam_start("login", user, &conv, &pamh);

    if(retval == PAM_SUCCESS) {
        retval = pam_authenticate(pamh, 0);  // Benutzer authentifizieren
    }

    if(retval == PAM_SUCCESS) {
        // Versuchen, das Authentifizierungstoken (Passwort) nach erfolgreicher Authentifizierung zu erhalten
        retval = pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL);

        if(retval == PAM_SUCCESS && authtok != NULL) {
            // Hinweis: Aus Sicherheitsgründen sollte das Passwort nicht ausgegeben oder ungeschützt gespeichert werden.
            printf("Authentifizierung erfolgreich, Authtok abgerufen.\n");
        } else {
            printf("Authentifizierung erfolgreich, aber Authtok konnte nicht abgerufen werden.\n");
            printf("error code %d\n", retval);
            printf("error %s\n", pam_strerror(pamh, retval));
        }
    } else {
        printf("Authentifizierung fehlgeschlagen: %s\n", pam_strerror(pamh, retval));
    }

    if(pam_end(pamh,retval) != PAM_SUCCESS) {
        pamh = NULL;
        fprintf(stderr, "Failed to release PAM transaction\n");
        exit(1);
    }

    return retval == PAM_SUCCESS ? 0 : 1;
}
