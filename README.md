Bachelorarbeit von Steven Schulz, Berliner Hochschule für Technik zum Thema "Transparente Verschlüsselung von Benutzerordnern unter dem Betriebssystem Linux".
Das geschriebene Skript installiert eine Anwendung, die im Nutzerverzeichnis zwei Ordner anlegt, "private" und ".private". Der "private" Ordner kann dazu genutzt werden, in Dateien zu schreiben, lesen, sie umzunennen, zu löschen und anzulegen. Dateien werden beim Schließen verschlüsselt und beim Öffnen entschlüsselt, während der Nutzer dies nicht wahrnimmt. Der ".private" Ordner sollte nicht genutzt werden, denn darin liegen die Dateien in verschlüsselter Form.
Die Anwendung wird bei jedem Authentifizieren gestartet und mountet ein Dateisystem auf das "private" Verzeichnis. Bei jedem Logout wird das Dateisystem von dem Verzeichnis getrennt.

Requirements:
- gcc
- pkg-config
- wget

Steps:
  - `git submodule init`
  - `git submodule update`
  - `sudo ./setup.sh`

Das `setup.sh` Skript geht folgende Schritte durch:
  - installiert development Libraries von PAM
  - installiert development Libraries von FUSE
  - installiert und testet Argon2
  - lädt libsodiums 1.0.19 Version herunter, entpackt diese und installiert es
  - kompiliert das PAM Modul und legt es in das dafür vorgesehene Verzeichnis
  - kompiliert das FUSE Dateisystem und legt dieses in /usr/bin
  - schreibt das PAM Modul in /etc/pam.conf oder /etc/pam.d/common-session und common-auth (somit kann es von PAM geladen werden)

Falls bei der Installation von Argon2 oder libsodium ein Error auftritt, können die Dokumentationen zur Installation hier gefunden und zur Hilfe genommen werden:
  - [Argon2 GitHub Usage(Installation)](https://github.com/P-H-C/phc-winner-argon2?tab=readme-ov-file#usage)
  - [libsodium Dokumentation zur Installation](https://libsodium.gitbook.io/doc/installation)
