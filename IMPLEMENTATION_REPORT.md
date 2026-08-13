# Implementation Report

## Ausgangszustand

Die unveränderte Baseline am 13. August 2026 war grün: Ruff, Ruff Format,
mypy strict und 43 Pytest-Tests bestanden. Coverage betrug 67 %. CLI,
Provider, LFS, Reflog, Submodule und mehrere Git-Plattformpfade waren kaum
oder gar nicht getestet.

## Gefundene Probleme

P0: rekonstruierbare kurze Secrets, rohe Remote-Credentials in Modellen und
Command-Beschreibungen, Timeout erst nach stdout-EOF, ungeprüfte Batch-OIDs,
harte 40-Zeichen-Annahmen, Profil-Placebos, still verschluckte
Detektorfehler, ungefiltertes ``findings --json``, uneinheitliche Sortierung
und fremder SARIF-Link.

## Behobene Security-Probleme

- Eine zentrale Redaction-Funktion liefert für Secrets bis einschließlich
  acht Zeichen keinerlei Originalfragmente.
- URL-Userinfo und credentialartige Querywerte werden zentral entfernt.
- Git-Fehler und Debug-Beschreibungen verwenden nur sanitisierte Argumente.
- ``batch_cat_file`` akzeptiert ausschließlich validierte SHA-1/SHA-256-OIDs.
- ``GitRunner.stream`` begrenzt die gesamte Laufzeit, leert stderr parallel
  und beendet Kinder auch bei frühem Consumer-Abbruch.
- Der bestehende globale SHA-256-Fingerprint bleibt für v0.1 bewusst erhalten;
  sein Offline-Guessing-Risiko ist im Threat Model dokumentiert.

## Behobene Correctness-Probleme

``findings --json`` besitzt ein eigenes Schema und respektiert Filter. Eine
gemeinsame Sortierfunktion ordnet critical, high, medium, low, info, danach
Score absteigend und ID. Detektorfehler erzeugen strukturierte Diagnostics
und ``complete=false``. Zentrale OID-Prüfung akzeptiert 4-40 oder 64 Hex-Zeichen.

## Profile

``secret_scan``, ``entropy_scan``, ``unreachable_objects``, ``reflogs``,
``stash``, ``notes`` und ``binary_scan`` steuern ihre Stufen. LFS-Fetch,
Submodule-Traversal und Provider sind für v0.1 ausdrücklich keine öffentlichen
Pipeline-Stufen. Die ausführbare Matrix wird durch Profiltests abgesichert.

| Stage | quick | standard | deep | forensic |
|---|---:|---:|---:|---:|
| Refs/reachable history | ja | ja | ja | ja |
| Pattern secrets | ja | ja | ja | ja |
| Entropy | nein | ja | ja | ja |
| Unreachable/lost chains | nein | nein | ja | ja |
| Reflogs/stash | nein | nein | ja | ja |
| Binary blobs | nein | nein | ja | ja |
| Git notes | nein | nein | nein | ja |

## CLI

Die vorhandene Command-Liste bleibt erhalten. Die Placebos ``--jobs`` und
``--fetch-lfs`` wurden entfernt. ``--fresh`` erzwingt nur Analyse,
``--refresh-remote`` aktualisiert den Mirror und ``--offline`` verbietet
Netzwerkzugriff. Cache-Services und Cache-Typer-Kommandos sind vom Hauptmodul
getrennt; die übrigen etablierten Commands bleiben zur v0.1-Kompatibilität im
Hauptmodul.

Öffentliche Commands: ``scan``, ``findings``, ``secrets``, ``refs``,
``commits``, ``objects``, ``dangling``, ``unreachable``, ``lost``,
``timeline``, ``authors``, ``stats``, ``history``, ``interesting``,
``explain``, ``explain-lost``, ``doctor``, ``report``, ``diff-scan``,
``baseline``, ``analyze churn`` sowie ``cache info/list/refresh/remove/prune``.
Die vollständige getestete Optionsreferenz steht in ``docs/usage.rst``;
``scan`` unterstützt Profile/Shorthands, Bloblimit, Fail-Threshold, Baseline,
Format/Output, Unshallow, Vendor-Inclusion, Fresh/Refresh/Offline und Debug.

## Git-Unterstützung

Die zentrale Grenze versteht SHA-1 und SHA-256; die wichtigsten 40-Zeichen-
Filter wurden entfernt. Echte Fixtures prüfen SHA-1/SHA-256 sowie shallow,
partial/promisor, bare, mirror und worktree.

## Tests

78 Tests bestehen, darunter neue Boundary-, Timeout-, stderr-, Iterator-
Cleanup-, OID-, URL-Sanitizing-, kurze-Secret- und Incomplete-Scan-Verträge.
Echte Fixtures decken SHA-1/SHA-256, bare, shallow, stash, reflog, notes,
Unicode-Dateinamen, binäre und größenbegrenzte Blobs sowie Vendor-Policy ab.
SARIF wird gegen das unveränderte offizielle SARIF-2.1.0-Schema validiert.

## Coverage

Ausgangswert 67 %, finaler Wert 72 %. CI erzwingt zunächst realistische 70 %;
Security-, Git-, Persistence- und Reporting-Kernpfade liegen überwiegend
deutlich darüber. Provider-Scaffolds sind nicht Teil der öffentlichen v0.1-
Oberfläche und bleiben bis zu einer späteren Aktivierung ungetestet.

## Performance

Lokaler Lauf (macOS, Python 3.13.5): Detector-Durchsatz für 1k/10k/100k
synthetische unique Blobs: 0,047 s / 0,460 s / 4,616 s. Laden eines echten,
per ``git fast-import`` erzeugten Commit-Graphen mit 100/1.000/10.000 Commits:
0,0066 s / 0,0193 s / 0,1549 s; gemessene Python-Peaks 0,26 / 2,58 / 25,85 MB.
Der reproduzierbare Treiber liegt unter ``benchmarks/run.py``.

## Storage

SQLite persistiert Scan-, Repository-, Ref-, Commit-, Finding-, Identitäts-
und redigierte Secret-Metadaten. Die Dokumentation behauptet nicht länger,
dass nichts persistiert werde. Schema-Version 2 wird transaktional und
idempotent migriert; POSIX-Verzeichnis-/DB-Rechte und atomische Outputs sind
durch Tests abgesichert.

## Documentation

Security/Privacy, Fingerprint-Tradeoff, Remote-Authentisierung,
CONTRIBUTING und Changelog wurden korrigiert. Die RTD-Struktur umfasst
Introduction, Installation, Concepts, Scanning, Commands, Detectors, Reports,
Configuration, Methodology, Performance, Security, Troubleshooting,
Compatibility und Development und baut mit Warnings-as-Errors.

## Packaging

Eine CI baut Dokumentation, Wheel und sdist und führt CLI-Smoke-Tests aus.
Lokal wurden ``refhound-0.1.0.tar.gz`` und das Wheel gebaut; eine isolierte
Wheel-Installation bestand ``--version``, ``--help``, ``scan --help`` und
``doctor --help``.

## Release Readiness

Die innerhalb von v0.1 bewusst unterstützte Oberfläche erfüllt die lokalen
Release-Gates. Nicht unterstützte Funktionen (Provider-API, LFS-Payload-Fetch,
rekursive Submodule, öffentliche Python-API) sind ausdrücklich deaktiviert
oder dokumentiert und werden nicht als fertig beworben. Externe Release-Aktionen
wie Git-Tag, GitHub Release und PyPI Trusted Publishing bleiben bewusst bei den
Maintainern; sie erfordern Zugangsdaten und Veröffentlichungsfreigabe.
