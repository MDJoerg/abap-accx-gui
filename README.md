# abap-accx-gui

*[Deutsch](#deutsch) below.*

Optional maintenance report of [Access Explorer (ACCX)](https://github.com/MDJoerg/abap-accx-base).
ABAP package `ZACCX_GUI`; it depends only on **abap-accx-base** (`ZACCX`), not on an MCP SDK.

The report `ZACCX_PROFILE_MAINTAIN` maintains the server profiles in table `ZACCX_PROFILE`: it
lists them, creates or changes one, or deletes one. The input is normalized and checked before
it is written, because a wrong row changes what a server offers: unknown privacy modes, tool
groups or classes and a row limit out of range are refused; a write permission without write
tools only warns. The **test run is the default**: it shows what would be saved and changes
nothing. Display needs `S_TABU_NAM` activity 03 for `ZACCX_PROFILE`, changes need activity 02;
every change is written to the audit log of ACCX.

## Install

1. Install **abap-accx-base** (package `ZACCX`).
2. Pull this repository into package `ZACCX_GUI` with abapGit.
3. Run report `ZACCX_PROFILE_MAINTAIN` (SE38 or a transaction you create for it).

A new profile becomes an endpoint when the adapter registers it: run `ZCL_ACCX_MCP2_SERVER` (or
`ZCL_ACCX_MCP1_SERVER`) with F9 afterwards.

More (profiles, privacy modes, tools, how the packages fit together) is documented in
**[abap-accx-base](https://github.com/MDJoerg/abap-accx-base)**.

## Deutsch

Optionaler Pflegereport von [Access Explorer (ACCX)](https://github.com/MDJoerg/abap-accx-base).
ABAP-Paket `ZACCX_GUI`; es hängt nur von **abap-accx-base** (`ZACCX`) ab, nicht von einem MCP-SDK.

Der Report `ZACCX_PROFILE_MAINTAIN` pflegt die Serverprofile in der Tabelle `ZACCX_PROFILE`: Er
listet sie auf, legt eines an oder ändert es, oder löscht es. Die Eingabe wird normalisiert und
geprüft, bevor sie geschrieben wird, weil eine falsche Zeile ändert, was ein Server anbietet:
unbekannte Datenschutzmodi, Werkzeuggruppen oder Klassen und ein Zeilenlimit außerhalb des
Bereichs werden abgewiesen; eine Schreiberlaubnis ohne Schreibwerkzeuge warnt nur. Der
**Testlauf ist voreingestellt**: Er zeigt, was gespeichert würde, und ändert nichts. Anzeigen
braucht `S_TABU_NAM` Aktivität 03 für `ZACCX_PROFILE`, Ändern Aktivität 02; jede Änderung wird im
Audit-Log von ACCX protokolliert.

### Installation

1. **abap-accx-base** (Paket `ZACCX`) installieren.
2. Dieses Repository mit abapGit in das Paket `ZACCX_GUI` ziehen.
3. Report `ZACCX_PROFILE_MAINTAIN` ausführen (SE38 oder eine dafür angelegte Transaktion).

Ein neues Profil wird zum Endpunkt, wenn der Adapter es registriert: danach `ZCL_ACCX_MCP2_SERVER`
(oder `ZCL_ACCX_MCP1_SERVER`) mit F9 ausführen.

Mehr (Profile, Datenschutzmodi, Tools, Zusammenspiel der Pakete) steht in
**[abap-accx-base](https://github.com/MDJoerg/abap-accx-base)**.
