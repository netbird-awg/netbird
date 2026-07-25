#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

CSV_ZIP_URL="https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip"
CSV_FILENAME="GeoLite2-City-Locations-en.csv"
DB_FILE="geonames_local.db"
TMP_DIR=$(mktemp -d)

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "==> Downloading GeoLite2-City-CSV ..."
curl -fSL -o "$TMP_DIR/geolite2-csv.zip" "$CSV_ZIP_URL"

echo "==> Extracting $CSV_FILENAME ..."
unzip -jo "$TMP_DIR/geolite2-csv.zip" "*/$CSV_FILENAME" -d "$TMP_DIR"

if [ ! -f "$TMP_DIR/$CSV_FILENAME" ]; then
    echo "ERROR: $CSV_FILENAME not found in zip" >&2
    exit 1
fi

echo "==> Building SQLite database ($DB_FILE) ..."
rm -f "$DB_FILE"

sqlite3 "$DB_FILE" <<'SQL'
CREATE TABLE geonames (
    geoname_id          INTEGER,
    locale_code         TEXT,
    continent_code      TEXT,
    continent_name      TEXT,
    country_iso_code    TEXT,
    country_name        TEXT,
    subdivision_1_iso_code TEXT,
    subdivision_1_name  TEXT,
    subdivision_2_iso_code TEXT,
    subdivision_2_name  TEXT,
    city_name           TEXT,
    metro_code          TEXT,
    time_zone           TEXT,
    is_in_european_union TEXT
);
.mode csv
.headers on
.import /dev/stdin geonames
SQL

python3 -c "
import csv, sqlite3, sys

conn = sqlite3.connect('$DB_FILE')
cur = conn.cursor()
cur.execute('DELETE FROM geonames')

with open('$TMP_DIR/$CSV_FILENAME', newline='', encoding='utf-8') as f:
    reader = csv.reader(f)
    header = next(reader)
    placeholders = ','.join(['?'] * len(header))
    for row in reader:
        cur.execute(f'INSERT INTO geonames VALUES ({placeholders})', row)

conn.commit()
count = cur.execute('SELECT COUNT(*) FROM geonames').fetchone()[0]
countries = cur.execute('SELECT COUNT(DISTINCT country_iso_code) FROM geonames WHERE country_name != \"\"').fetchone()[0]
cities = cur.execute('SELECT COUNT(DISTINCT city_name) FROM geonames WHERE city_name != \"\"').fetchone()[0]
conn.close()
print(f'==> Imported {count} records  ({countries} countries, {cities} cities)')
"

echo "==> Done: $(ls -lh "$DB_FILE" | awk '{print $5}')  $DB_FILE"
echo ""
echo "Files ready in deploy/:"
echo "  GeoLite2-City.mmdb      (IP geolocation)"
echo "  geonames_local.db       (city/country names)"
