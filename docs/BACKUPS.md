# Backups and restore

The app creates a SQLite-consistent backup at startup if today's UTC backup is missing, then checks hourly. Backups contain the database, Data Protection keys, and a SHA-256 manifest. They live under `/data/backups` in Docker or `backups` inside `AGGRO_DATA_DIR`.

Retention keeps the latest snapshot for each of seven days and one per older week for four weeks. Failures appear in application logs. Copy backups to a separate, access-controlled location. They contain collected data and encryption keys.

## Restore a copy

Choose an existing backup and a new destination directory. In Compose, run the following command with your backup directory name.

```sh
docker compose run --rm --entrypoint dotnet threat-intel-aggro ThreatIntelAggro.dll --restore-backup /data/backups/<backup-directory> /data/restored-check
```

For a local build, use `dotnet ThreatIntelAggro.dll --restore-backup <backup-directory> <new-data-directory>`.

Restore verifies the manifest, hashes, and database, then copies into the new destination. The destination must not exist. Test the restored copy separately. Stop the app before switching storage, retain the original directory, and move the restored database and Data Protection keys together.
