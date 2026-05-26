from airflow.sdk import DAG
from airflow.datasets import Dataset
from airflow.providers.http.operators.http import HttpOperator
from airflow.providers.standard.operators.python import PythonOperator
from airflow.providers.postgres.hooks.postgres import PostgresHook
import pandas as pd
from io import StringIO
import socket
import struct
import datetime

# mes fonctions utilitaires simples

def ip_to_int(ip: str) -> int:
    s = str(ip).strip()
    try:
        if '.' in s:
            return struct.unpack('!I', socket.inet_aton(s))[0]
        return int(float(s))
    except Exception:
        return -1


# Dataset représentant l'extraction du fichier de logs publics
dataset_logs = Dataset('http://httpdata_nginx_intrusion/public_network_logs.csv')

# DAG 1 : traitement du fichier de log
with DAG(
    dag_id='dag_intrusion_log',
    schedule=None,
    start_date=datetime.datetime(2026, 1, 1),
    catchup=False,
):
    # Récupère le fichier de logs via HTTP. Déclare l'outlet dataset pour déclencher d'autres DAGs.
    fetch_logs = HttpOperator(
        task_id='extract_pub_log',
        http_conn_id='httpdata_nginx_intrusion',
        endpoint='public_network_logs.csv',
        method='GET',
        outlets=[dataset_logs],
    )

    def filter_and_store_logs(ti):
        # Récupère le contenu depuis l'XCom (HttpOperator pousse la réponse)
        raw = ti.xcom_pull(task_ids='extract_pub_log')
        if isinstance(raw, list):
            raw = '\n'.join(raw)
        df = pd.read_csv(StringIO(raw))
        # On garde les colonnes utiles
        cols = ['Source_IP', 'Destination_IP', 'Port', 'Request_Type', 'Payload_Size', 'User_Agent', 'Status', 'Intrusion']
        df_filtered = df[cols]
        # Stocke localement pour réutilisation (simple stockage temporaire)
        df_filtered.to_csv('/tmp/filtered_intrusion.csv', index=False)
        print('Logs filtrés enregistrés dans /tmp/filtered_intrusion.csv')

    store_logs = PythonOperator(task_id='filter_and_store_logs', python_callable=filter_and_store_logs)

    fetch_logs >> store_logs


# DAG 2 : alimentation de l'inventaire IP->Pays
# Ce DAG est déclenché automatiquement lorsque `dataset_logs` est mis à jour (Dataset Aware Scheduling)
with DAG(
    dag_id='dag_intrusion_pays',
    schedule=[dataset_logs],
    start_date=datetime.datetime(2026, 1, 1),
    catchup=False,
):
    # Télécharge le fichier d'inventaire des IP->Pays
    fetch_inventory = HttpOperator(
        task_id='fetch_inventory',
        http_conn_id='httpdata_nginx_intrusion',
        endpoint='dbip-country-lite-2026-01.csv',
        method='GET',
    )

    def build_inventory(ti):
        # Récupère le CSV depuis l'XCom et construit un fichier local compressé (format parquet)
        raw = ti.xcom_pull(task_ids='fetch_inventory')
        if isinstance(raw, list):
            raw = '\n'.join(raw)
        df = pd.read_csv(StringIO(raw), names=['ip_start_range', 'ip_end_range', 'country_code'])
        # Convertit en entiers pour accélérer les recherches ultérieures
        df['ip_start_int'] = df['ip_start_range'].apply(ip_to_int)
        df['ip_end_int'] = df['ip_end_range'].apply(ip_to_int)
        # Enregistre un inventaire local prêt à l'emploi (CSV pour éviter dépendances parquet)
        df.to_csv('/tmp/ip_inventory.csv', index=False)
        print('Inventaire IP->Pays enregistré dans /tmp/ip_inventory.csv')

    store_inventory = PythonOperator(task_id='build_inventory', python_callable=build_inventory)

    fetch_inventory >> store_inventory


# DAG 3 (optionnel) : applique la correspondance IP->Pays et stocke en base
with DAG(
    dag_id='dag_intrusion_db',
    schedule=[dataset_logs],
    start_date=datetime.datetime(2026, 1, 1),
    catchup=False,
):
    # On récupère le log filtré (stocké localement par dag_intrusion_log) et l'inventaire local
    def map_and_insert():
        # Lecture fichiers locaux (si absents, on peut aussi re-télécharger)
        try:
            df_logs = pd.read_csv('/tmp/filtered_intrusion.csv')
        except Exception:
            print('Fichier /tmp/filtered_intrusion.csv introuvable, arrêt du DAG')
            return
        try:
            df_inv = pd.read_csv('/tmp/ip_inventory.csv')
        except Exception:
            print('Fichier /tmp/ip_inventory.csv introuvable, arrêt du DAG')
            return

        # Fonction de recherche simple
        def find_country(ip):
            i = ip_to_int(ip)
            if i < 0:
                return 'UNKNOWN'
            rows = df_inv[(df_inv['ip_start_int'] <= i) & (df_inv['ip_end_int'] >= i)]
            if not rows.empty:
                return rows.iloc[0]['country_code']
            return 'UNKNOWN'

        df_logs['country_code'] = df_logs['Source_IP'].apply(find_country)

        # Insertion en base Postgres
        hook = PostgresHook(postgres_conn_id='datawarehouse')
        create_sql = '''
        CREATE TABLE IF NOT EXISTS intrusion_events (
            source_ip TEXT,
            destination_ip TEXT,
            port TEXT,
            request_type TEXT,
            payload_size TEXT,
            user_agent TEXT,
            status TEXT,
            intrusion TEXT,
            country_code TEXT
        );
        '''
        hook.run(create_sql)

        cols = ['Source_IP', 'Destination_IP', 'Port', 'Request_Type', 'Payload_Size', 'User_Agent', 'Status', 'Intrusion', 'country_code']
        rows = df_logs[cols].values.tolist()
        if rows:
            hook.insert_rows(table='intrusion_events', rows=rows, target_fields=[c.lower() if c != 'country_code' else 'country_code' for c in cols])
        print(f'Inséré {len(rows)} lignes dans intrusion_events')

    task_map_insert = PythonOperator(task_id='map_and_insert', python_callable=map_and_insert)

    task_map_insert
