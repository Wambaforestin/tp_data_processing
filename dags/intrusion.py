from airflow.sdk import DAG
# EmptyOperator n'est pas utilisé ici
from airflow.providers.http.operators.http import HttpOperator
from airflow.providers.standard.operators.python import PythonOperator
import pandas as pd
from io import StringIO
import socket
import struct
from airflow.providers.postgres.hooks.postgres import PostgresHook
# typing.Any n'est plus nécessaire



def process_filter_ipv4(task_instance):
    # # Solution without xcom
    # df_solution1 = pd.read_csv('http://httpdata_nginx_intrusion/public_network_logs.csv')
    # Solution with xcom
    # Récupère le texte CSV brut depuis l'XCom du HttpOperator (gère chaîne ou liste)
    raw = task_instance.xcom_pull(task_ids='extract_dbip')
    if isinstance(raw, list):
        raw = '\n'.join(raw)
    df = pd.read_csv(StringIO(raw), names=['ip_start_range', 'ip_end_range', 'country_code'])

    # Normalise les plages d'IP : convertir en entiers IPv4 via `ip_to_int_safe`
    df['ip_start_int'] = df['ip_start_range'].apply(ip_to_int_safe)
    df['ip_end_int'] = df['ip_end_range'].apply(ip_to_int_safe)

    # Conserve uniquement les lignes ayant des plages IPv4 valides
    df_filtered = df[(df['ip_start_int'] >= 0) & (df['ip_end_int'] >= df['ip_start_int'])]
    print(f'Avant filtre: {len(df)}, Après filtre: {len(df_filtered)}')
    return df_filtered

def process_filter_remove_col(task_instance):
    # Récupère le CSV des logs publics depuis l'XCom
    raw = task_instance.xcom_pull(task_ids='extract_pub_log')
    if isinstance(raw, list):
        raw = '\n'.join(raw)
    df = pd.read_csv(StringIO(raw))
    # Colonnes attendues : Source_IP,Destination_IP,Port,Request_Type,Protocol,Payload_Size,User_Agent,Status,Intrusion,Scan_Type
    # On conserve uniquement les colonnes pertinentes
    df_filtered = df[['Source_IP', 'Destination_IP', 'Port', 'Request_Type', 'Payload_Size', 'User_Agent', 'Status', 'Intrusion']]
    return df_filtered

def process_convert_ipv4(task_instance):
    # Fonction de contrôle : affiche un aperçu du DataFrame des plages IPv4
    df = task_instance.xcom_pull(task_ids='filter_ipv4')
    if isinstance(df, list):
        df = df[0]
    print(df.head(2))
    print(type(df))
    
def process_convert_ipv4_pub(task_instance):
    # Fonction de contrôle : affiche un aperçu du DataFrame des logs publics filtrés
    df = task_instance.xcom_pull(task_ids='filter_remove_col')
    if isinstance(df, list):
        df = df[0]
    print(df.head(2))
    print(type(df))


def ip_to_int_safe(ip: str) -> int:
    s = str(ip).strip()
    try:
        if '.' in s:
            return struct.unpack('!I', socket.inet_aton(s))[0]
        return int(float(s))
    except Exception:
        return -1


def map_ip_to_country_and_insert(task_instance):
    # Pull processed dataframes from XCom
    df_ip = task_instance.xcom_pull(task_ids='filter_ipv4')
    if isinstance(df_ip, list):
        df_ip = df_ip[0]

    df_pub = task_instance.xcom_pull(task_ids='filter_remove_col')
    if isinstance(df_pub, list):
        df_pub = df_pub[0]

    if df_ip is None or df_pub is None:
        print('Données d\'entrée manquantes pour le mapping')
        return

    # Ensure integer ip ranges exist
    if 'ip_start_int' not in df_ip.columns:
        df_ip['ip_start_int'] = df_ip['ip_start_range'].apply(ip_to_int_safe)
    if 'ip_end_int' not in df_ip.columns:
        df_ip['ip_end_int'] = df_ip['ip_end_range'].apply(ip_to_int_safe)

    # Map country for each Source_IP
    def find_country(src_ip):
        ip_int = ip_to_int_safe(src_ip)
        if ip_int < 0:
            return 'UNKNOWN'
        mask = (df_ip['ip_start_int'] <= ip_int) & (df_ip['ip_end_int'] >= ip_int)
        rows = df_ip[mask]
        if not rows.empty:
            return rows.iloc[0]['country_code']
        return 'UNKNOWN'

    df_pub['country_code'] = df_pub['Source_IP'].apply(find_country)

    # Insert into Postgres (datawarehouse)
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

    # Prepare rows
    cols = ['Source_IP', 'Destination_IP', 'Port', 'Request_Type', 'Payload_Size', 'User_Agent', 'Status', 'Intrusion', 'country_code']
    rows = df_pub[cols].replace({pd.NA: None}).values.tolist()
    if rows:
        hook.insert_rows(table='intrusion_events', rows=rows, target_fields=[c.lower() if c != 'country_code' else 'country_code' for c in cols])
    print(f'Inséré {len(rows)} lignes dans intrusion_events')
    return len(rows)

with DAG(dag_id='intrusion'):
    extract_dbip = HttpOperator(
        task_id='extract_dbip',
        method='GET',
        endpoint='dbip-country-lite-2026-01.csv',
        http_conn_id='httpdata_nginx_intrusion'
        )
    extract_pub_log = HttpOperator(
        task_id='extract_pub_log',
        method='GET',
        endpoint='public_network_logs.csv',
        http_conn_id='httpdata_nginx_intrusion'
    )
    filter_ipv4 = PythonOperator(
        task_id='filter_ipv4',
        python_callable=process_filter_ipv4)
    convert_into_ipv4 = PythonOperator(
        task_id='convert_into_ipv4',
        python_callable=process_convert_ipv4
        )
    filter_remove_col = PythonOperator(
        task_id='filter_remove_col',
        python_callable=process_filter_remove_col)
    convert_into_ipv4_pub = PythonOperator(
        task_id='convert_into_ipv4_pub',
        python_callable=process_convert_ipv4_pub)
    map_ip_country = PythonOperator(task_id='map_ip_country', python_callable=map_ip_to_country_and_insert)
    load = PythonOperator(task_id='finalize', python_callable=lambda: print('pipeline intrusion terminé'))

    extract_dbip >> filter_ipv4 >> convert_into_ipv4
    extract_pub_log >> filter_remove_col >> convert_into_ipv4_pub
    [convert_into_ipv4, convert_into_ipv4_pub] >> map_ip_country >> load