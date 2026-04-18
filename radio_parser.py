import zipfile
import re
import sqlite3
import os

# --- Налаштування та Регулярні вирази ---
ecid_num_re = re.compile(r"sys\.data\.ecid(\d+)")
hwid_archive_re = re.compile(r"sys\.data\.hwid[0-9a-fA-F]{8}\.certifications\.bar")
pps_re = re.compile(r"^([\w\d_-]+):([\w\d]*):(.*)$")

class PPSDatabase:
    def __init__(self, db_path='pps_normalized.db'):
        self.conn = sqlite3.connect(db_path)
        self._setup_tables()
        # Кеш для прискорення вставки (щоб не робити SELECT перед кожним INSERT)
        self.cache = {'devices': {}, 'objects': {}, 'params': {}}

    def _setup_tables(self):
        cursor = self.conn.cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ecid TEXT,
                hwid TEXT,
                UNIQUE(ecid, hwid)
            );
            CREATE TABLE IF NOT EXISTS objects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pps_path TEXT UNIQUE
            );
            CREATE TABLE IF NOT EXISTS params (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                type TEXT,
                UNIQUE(name, type)
            );
            CREATE TABLE IF NOT EXISTS pps_values (
                device_id INTEGER,
                object_id INTEGER,
                param_id INTEGER,
                source_type TEXT,
                value TEXT,
                PRIMARY KEY (device_id, object_id, param_id, source_type),
                FOREIGN KEY (device_id) REFERENCES devices(id),
                FOREIGN KEY (object_id) REFERENCES objects(id),
                FOREIGN KEY (param_id) REFERENCES params(id)
            );

            CREATE VIEW IF NOT EXISTS v_full_data AS
            SELECT d.ecid, d.hwid, o.pps_path, p.name, p.type, v.source_type, v.value
            FROM pps_values v
            JOIN devices d ON v.device_id = d.id
            JOIN objects o ON v.object_id = o.id
            JOIN params p ON v.param_id = p.id;
        ''')
        self.conn.commit()

    def get_id(self, table, identifier, insert_sql, params):
        """Універсальний метод для отримання ID з кешу або бази"""
        if identifier in self.cache[table]:
            return self.cache[table][identifier]

        cursor = self.conn.cursor()
        cursor.execute(insert_sql, params)
        self.conn.commit()

        # Отримуємо ID (або щойно створений, або існуючий)
        lookup_sql = f"SELECT id FROM {table} WHERE " + " AND ".join([f"{k}=?" for k in params.keys()])
        cursor.execute(lookup_sql, tuple(params.values()))
        row_id = cursor.fetchone()[0]

        self.cache[table][identifier] = row_id
        return row_id

    def add_entry(self, ecid, hwid, pps_path, source_type, param_name, p_type, value):
        dev_id = self.get_id('devices', f"{ecid}|{hwid}",
                             "INSERT OR IGNORE INTO devices (ecid, hwid) VALUES (:ecid, :hwid)",
                             {'ecid': ecid, 'hwid': hwid})

        obj_id = self.get_id('objects', pps_path,
                             "INSERT OR IGNORE INTO objects (pps_path) VALUES (:pps_path)",
                             {'pps_path': pps_path})

        param_id = self.get_id('params', f"{param_name}|{p_type}",
                               "INSERT OR IGNORE INTO params (name, type) VALUES (:name, :type)",
                               {'name': param_name, 'type': p_type})

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO pps_values (device_id, object_id, param_id, source_type, value)
            VALUES (?, ?, ?, ?, ?)
        ''', (dev_id, obj_id, param_id, source_type, value))

    def commit(self):
        self.conn.commit()

def get_ecid_from_filename(filename):
    if hwid_archive_re.search(filename): return None
    if "ecidcommon" in filename or "ecidtemplate" in filename: return "0"
    match = ecid_num_re.search(filename)
    return match.group(1) if match else None

def process_archives(directory):
    db = PPSDatabase()
    files = [f for f in os.listdir(directory) if f.endswith(".bar")]

    for filename in files:
        ecid = get_ecid_from_filename(filename)
        if not ecid: continue

        print(f"[*] Processing: {filename}")

        try:
            with zipfile.ZipFile(os.path.join(directory, filename), 'r') as z:
                for path in z.namelist():
                    if '/pps/' in path and not path.endswith('/'):
                        parts = path.split('/')
                        source_type = "pushed" if "pushed" in parts else "default"

                        # Знаходимо HWID (8 hex)
                        hwid = next((p for p in parts if len(p) == 8 and all(c in "0123456789ABCDEFabcdef" for c in p)), "00000000")

                        pps_idx = path.find('pps/')
                        rel_path = path[pps_idx:]

                        with z.open(path) as f:
                            for line in f:
                                try:
                                    line_str = line.decode('utf-8', errors='ignore').strip()
                                    if not line_str or line_str.startswith('@'): continue

                                    if line_str.startswith('-'):
                                        db.add_entry(ecid, hwid, rel_path, source_type, line_str[1:], 'deleted', '')
                                        continue

                                    match = pps_re.match(line_str)
                                    if match:
                                        p_name, p_type, p_val = match.groups()
                                        db.add_entry(ecid, hwid, rel_path, source_type, p_name, p_type, p_val)
                                except: continue
                db.commit()
        except Exception as e:
            print(f"[!] Error {filename}: {e}")

    print("\n[+] Done! Database 'pps_normalized.db' is ready.")

if __name__ == "__main__":
    process_archives('/home/lc/RE/RIM/BB10.OS/3216.p/seed/bars')
