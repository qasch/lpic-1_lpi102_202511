# Dokumentation Schulung Linux Nov 2025

## Benutzerkonten

### Root Acount

Der Benutzer `root` ist der *SuperUser* eines Linux Systems. Er ist der einzige Benutzer, welcher volle Rechte auf das System hat, also alles darf. Er muss auf jedem System existieren, damit dieses lauffähig ist, beispielsweise um während des Bootvorgangs einzelne Dienste zu starten usw.

### Reguläre Benutzer

Alle *regulären* Benutzer haben **eingeschränkte** Rechte. Sie dürfen z.B. nicht alle Kommandos ausführen oder generell irgendwelche Änderungen am System vornehmen. 

Im Hintergrund wird das mehr oder weniger alles über die Berechtigungen an Dateien geregelt.

Reguläre Benutzer können sich am System anmelden und interaktiv Kommandos ausführen. Dazu haben sie in der `/etc/passwd` eine *Login Shell* zugewiesen.

### Systembenutzer / Servicenutzer / Pseudobenutzer

Es gibt eine weitere Bentuzergruppe mit eingeschränkten Rechten. Das fällt uns auf, wenn wir die Datei `/etc/passwd` inspizieren. Die Mehrzahl der Benutzer haben wir gar nicht selbst angelegt, sie wurden automatisch vom System erzeugt, als bestimmte Dienste/Services installiert wurden.

Genau das ist der Sinn dieser Benutzer: So können bestimmte Dienste bzw. Prozesse mit deren Berechtigungen ausgeführt werden um die Sicherheit des Systems zu erhöhen. Ein kompromittierter Dienst erhält so also nicht direkt Zugriff auf das gesamte System.

Beispiel: `www-data` für Webserver wie *Apache oder Nginx* - selbst wenn ein Angreifer den Webserver übernimmt, kann er nicht auf andere Systemdateien zugreifen.

Pseudobenutzer haben keine Login-Shell, ihnen wird `/usr/sbin/nologin` zugewiesen. Sie können sich also nicht am System anmelden und Kommandos ausführen.

### Benutzer anlegen mit `useradd`

Mit `useradd` (auf allen Linux Systemen verfügbar) können wir Benutzer anlegen.

Obwohl ein Eintrag für ein Home-Verzeichnis in der `/etc/passwd` erzeugt wird, wird dies **nicht** angelegt
```bash
useradd <user>
```
Die Option `-m` bewirkt, dass unterhalb von `/home` ein Verzeichnis mit dem Namen des Benutzers erzeugt und alle Dateien aus `/etc/skel` dorthin kopiert werden.
```bash
useradd -m <user>
useradd --create-home <user>
```
Benutzer eine Login-Shell zuweisen
```bash
useradd -s /bin/bash <user>
useradd --shell /bin/bash <user>
```
Kommentarfeld für den vollen Namen des Benutzers und weitere Informationen
```bash
useradd -c "Voller Name des Benutzers" <user>
useradd --comment "Voller Name des Benutzers" <user>
```
Neuen User eine bestimmte Primäre Gruppe zuordnen:
```bash
useradd -g <primary-group> <user>
```
Neuen User einer Liste von zusätzlichen Gruppen zuordnen:
```bash
useradd -G <supplementary-group-1>,<supplementary-group-2> <user>
```
Standarbeispiel zum Anlegen eines Benutzers:
```bash
useradd -m -c "Tux Tuxedo" -s /bin/bash tux
```

useradd -p 
### Passwörter
Passwörter werden nicht in der `/etc/passwd` gespeichert, sondern in der Datei `/etc/shadow`. Dafür gibt es mindestens zwei Gründe:

1. Die Datei `/etc/passwd` muss von allen Usern auf dem System lesbar sein, wir wollen aber vermeiden, dass die Passwort-Hashes auslesbar sind
2. In der Datei `/etc/passwd` werden Informationen über die User gespeichert, in der `/etc/shadow` Informationen über Passwörter (*Separation of Concern*)

Passwörter liegen sind immer gehasht und zusätzlich gesaltet, d.h. dass vor dem Hashen des Passworts eine bestimmte zufällig generierte Zeichenkette vor das Passwort geschrieben und dann der kommplette String (Salt + Passwort) gehasht wird.

So wird zum einen vermieden, dass zwei gleiche Klartextpasswörter den gleichen Hash erhalten, zum anderen werden Attacken über *Rainbow Tables* (riesige Tabellen mit Hash-Werten und den dazugehörigen Klartextpasswörtern) vermieden.

Das Kommando `useradd` kann selbst keine Passwörter generieren! Wir rufen dazu nach dem Erstellen eines neuen Users das Kommando `passwd` auf.

>[!NOTE] 
> Wir können dem Benutzer auch bereits beim Erzeugen ein Passwort mitgeben. 

**Wichtig:** Hier muss ein für das System passender *gesaltener* HASH angegeben werden. Der Eintrag wird exakt so in die `/etc/shadow` eingetragen.
```bash
useradd -p "PASSWORDHASH" <user>
useradd --password "PASSWORDHASH" <user>
```
Schwer ist das nicht wirklich - wir können dazu das Kommando `openssl` verweden:
```bash
openssl passwd -6 PASSWORT
```
Die Option `-6` weist `openssl` an, den für Linux empfohlenen sicheren *SHA-512* Algorithmus zu verwenden.

In einem Rutsch sähe das folgendermassen aus:
```bash
useradd -m -c "User mit Passwort" -p $(openssl passwd -6 'My!Secret#Password') -s /bin/bash userwithpass
```
#### Relevante Dateien
Beim Anlegen von Benutzern passiert übrigens nur folgendes:

- Ein Eintrag in der `/etc/passwd` mit den Benutzerinformationen wird erzeugt
- Das Passwort wird in die `/etc/shadow` eingetragen
- Die primäre Gruppe wird zur `/etc/group` hinzugefügt (und eventuell andere Gruppenzugehörigkeiten angepasst)
- In der `/etc/gshadow` wird ein Eintrag ohne Passwort erzeugt (diese Datei bzw. Gruppenpasswörter werden eh nicht genutzt)

Nutzen wir die Option `-m` zum Anlegen eines Heimatverzeichnisses mit Standarddateien wird diese noch zusätzlich erstellt, alle Dateien aus `/etc/skel` dorhinein kopiert und die Berechtigungen angepasst.

Das war's. Nichts weiter. Keine Magie, nichts im Hintergrund. Nur Veränderung von Textdateien. Das ist ein gutes Beispiel dafür, wie die Konfiguration eines Linux System generell funktioniert. 

### passwd
Das Kommando ermöglicht die Änderung von Passwörtern. Mit Root-Rechten können so die Passwörter aller Benutzer geändert werden:
```bash
passwd <user>
```
Als regulärer Benutzer kann man damit sein eigenes Paswsort ändern:
```bash
passwd
```
Nutzen wir `useradd`, führen wir in der Regel dieses Kommando direkt im Anschluss aus, ansonsten hat der User kein Paswsort und kann sich nicht am System anmelden!

### chsh
Mit `chsh` kann ein Benutzer seine Login Shell selbst ändern bzw. kann `root` die Login Shells jedes Users ändern.
```bash
chsh -s /bin/bash
```
### Benutzerkonfiguration ändern

Mit dem Kommando `usermod` können wir die Benutzerkonfiguration nachträglich wieder ändern. Die Optionen sind denen von `useradd` sehr ähnlich. 

Ändern der Login Shell von `korni` zur `ksh`:

```bash
usermod -s /usr/bin/ksh korni
```
### adduser

`adduser` ist ein Perl-Skript, welches u.a. die Kommandos  `useradd` und `passwd` ausführt. Es ist *interaktiv*, wir brauchen keine Optionen zu übergeben, bestimmte Einstellungen werden abgefragt, vor allem fragt `adduser` direkt nach einem Passwort für den neuen Benutzer. Es sind andere Default-Werte gesetzt als bei `useradd`, z.B. die `bash` als Login-Shell.

Dieses Kommando ist aber standardmässig nur auf Debian-basierten Distributionen vorinstalliert.

#### Relevante Dateien
Beim Anlegen von Benutzern passiert übrigens nur folgendes:

- Ein Eintrag in der `/etc/passwd` mit den Benutzerinformationen wird erzeugt
- Das Passwort wird in die `/etc/shadow` eingetragen
- Die primäre Gruppe wird zur `/etc/group` hinzugefügt (und eventuell andere Gruppenzugehörigkeiten angepasst)
- In der `/etc/gshadow` wird ein Eintrag ohne Passwort erzeugt (diese Datei bzw. Gruppenpasswörter werden eh nicht genutzt)

Das war's. Nichts weiter. Keine Magie, nichts im Hintergrund. Nur Veränderung von Textdateien. Das ist ein gutes Beispiel dafür, wie die Konfiguration eines Linux System generell funktioniert. 

## Gruppen
Mit Gruppen können mehrere Benutzer zusammengefasst und ihnen gemeinsame Berechtigungen auf Dateien und Verzeichnisse gegeben werden.

Im Unterschied zu Windows können Gruppen nur einzelne Benutzer enthalten, keine weiteren Gruppen.

Für die Anzeige der Gruppenzugehörigkeiten kann man die Kommandos `groups` oder `id` benutzen.

#### Primäre Gruppe
Jeder Benutzer hat genau eine primäre Gruppe. Diese ist in `/etc/passwd` eingetragen. In der Regel hat sie den gleichen Namen wie der Benutzer. Sie ist nötig, da z.B. beim Erstellen von Dateien diese einem Benutzer und einer Gruppe zugewiesen werden.

#### Sekundäre Gruppen
Ein Benutzer kann aber auch mehreren zusätzlichen Gruppen angehören. Die Zugehörigkeiten sind in der `/etc/group` eingetragen.

### Gruppe erstellen:
Auf allen Linux Systemen existiert das Kommando `groupadd`
```bash
groupadd <gruppe>
```
### Benutzer einer Gruppe hinzufügen:
Auch die Gruppenzugehörigkeiten passen wir mit dem Kommando `usermod` an:
```bash
usermod -g <primary-group> <user>
usermod -G <absolute-list-of-supplementary-groups> <user>
usermod -G <group1>,<group2>,<group3>,<newgroup> <user>
usermod -aG <newgroup> <user>
```
Vorsicht mit der Option `-G`, diese erwartet eine absolute Liste von Gruppen, die der User angehören soll. Gehört der User einer Gruppe an, die hier nicht genannt ist, wird er aus dieser Gruppen entfernt.

Möchten wir einen User einer Gruppe hinzufügen, die bestehenden Gruppenzugehörigkeiten aber nicht verändern, nutzen wir zusätzlich die Opione `-a` (steht für `--append`).

Damit Gruppenzugehörigkeiten gültig werden, muss die Datei `/etc/group` neu eingelesen werden. Dies geschieht z.B. wenn der Benutzer muss sich neu anmeldet bzw. eine neue Login-Shell startet. 

Um die Gruppenzugehörigkeit in der aktuellen Shell zu aktualisieren, kann auch das Kommando `newgrp <gruppe>` genutzt werden.

## Cron

Cron ist ein Dienst, der Aufgaben (`cronjobs`) zu einem bestimmmten Zeitpunkt oder Zeitintervall automatisch ausführt. Cron wacht selbständig jede Minute auf, prüft bestimmte Dateien nach anstehenden Aufgaben und führt diese ggf. dann aus.

- `cronjobs` werden **nicht** nachgeholt, sollte der Rechner zu dem angegebenen Zeitpunkt aus sein, eignen sich also eher für Server als für Desktop Systeme
- Aufgaben werden in sog. `crontabs` festgelegt
- es gibt User `crontabs` für jeden Benutzer (auch für `root`) und eine systemweite `crontab` unter `/etc/crontab`
- diese unterscheidet sich von den User-crontabs (nur) dadurch, dass es eine zusätzliche Spalte für den auszuführeden Benutzer gibt
- in den Verzeichnissen `/etc/cron.hourly`, `/etc/cron.daily` usw. können Skripte abgelegt werden, die dann periodisch ausgeführt werden
- je nach Distribution können die Verzeichnisse auch `/etc/cron.d/daily` etc. heissen
- User crontabs liegen z.B. unter `/var/spool/cron/crontabs` (distributionsabhängig)
- die User crontab Dateien werden nicht direkt editiert, sondern mit dem Kommando `crontab -e`
- `crontab -r` löscht die crontab des aufrufenden Benutzers
- `crontab -l` zeigt den Inhalt der crontab an
- `root` kann eine User crontab mit dem Kommando `crontab -u <user> -e / -l / -r` editieren, auflisten oder löschen
- Informationen über den Aufbau und die Angabe von Zeiten/Intervallen sind in der Manpage zu finden: `man 5 crontab`, Informationen über das Kommando `crontab` unter `man crontab`
- in den Dateien `/etc/cron.allow` und `/etc/cron.deny` koenne Zugriffe auf den cron Daemon geregelt werden
- existiert die Datei `/etc/cron.allow` können _ausschliesslich_ die darin gelisteten Benutzer (einer pro Zeile) `cron` benutzen
- existiert die Datei `/etc/cron.deny` und *keine* `/etc/cron.allow` können alle *nicht* darin gelisteten Benutzer (einer pro Zeile) `cron` benutzen
- existieren beide Dateien, wird nur `/etc/cron.allow` ausgelesen

Format Angabe Zeitintervalle:
```
 .---------------- minute (0 - 59)
 |  .------------- hour (0 - 23)
 |  |  .---------- day of month (1 - 31)
 |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
 |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
 |  |  |  |  |
 *  *  *  *  * command to be executed
```
- Es können spezifische Zeitpunkte, Listen von Zeitpunkten (durch Komma getrennt), Bereiche (durch Minuszeichen getrennt) oder Intervalle (Angabe mit Slash `/`) angegebenen werden. Beispiele:

- `mon,tue,thu`    -> Montag, Dienstag und Donnerstag
- `mon-sat`        -> Montag bis Samstag
- `9-16`           -> 9 bis 16 Uhr
- `*/5`          -> alle fünf (z.B. Minuten)

## Systemd Timer

Systemd Timer sind eine Alternative von `systemd` für `cron`.

Ein grosser Unterschied ist hier, dass Timer über Systemd Unit Files konfiguriert werden. Diese sind einmal Unit Files mit der Endung `.timer`, in denen das Zeitintervall festgelegt wird.Für jeden Timer muss zusätzlich ein Service File vorliegen (`.service`), welches den Service beschreibt, der zu den im Timer angegebenen Zeitpunkt gestartet wird.

Timer und Service Files müssen den gleichen Namen (bis auf die Endung) haben.

**Beispiel:** 

Starte den Service `/etc/systemd/system/foobar.service` um 05:30 Uhr am ersten Montag jeden Monats. Falls der Rechner zu diesem Zeitpunkt nicht an sein sollte wird der Timer nachgeholt sobald der Rechner wieder startet (`Persistent=true`):
```
[Unit]
Description=Run the foobar service

[Timer]
OnCalendar=Mon *-*-1..7 05:30:00
Persistent=true

[Install]
WantedBy=timers.target
```
- Syntax bzw. Aufbau der `OnCalendar=` Einträge sind etwas anders als in Crontabs:
```
# DayOfWeek Year-Month-Day  Hour:Minute:Second

  Mon       *   - *    1..7 05:30:00

# Alternative Angaben:

  hourly
  daily
  weekly
  monthly
  yearly
```

generelle Syntax zu Zeitangaben in `systemd` in Manpage `man systemd.time`, spezifischer für Timer unter `CALENDAR EVENTS` bzw. ganz unten in der Manpage zu finden.

- Angabe der Spalte `DayOfWeek` ist optional
- `*`, `/` und `,` wie in crontabs
- mit `..` kann eine Range angegeben werden (wie `-` in crontabs)
- `timer` müssen wie `services` aktiviert bzw. gestartet werden:
```
systemctl enable foobar.timer
systemctl start foobar.timer

# Alternativ, aktiveren und starten in einem Kommando:
systemctl enable --now foobar.timer
```
- nach einer Änderung an den Unit Files muss noch das Kommando `systemctl daemon-reload` ausgeführt werden
- es können auch sog. _Monotonic Timers_ verwendet werden (`systemd-run`)
- diese werden nach Ablauf einer gewissen Zeit aktiviert (ähnlich wie `at`)














