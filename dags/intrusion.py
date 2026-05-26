from airflow.sdk import DAG
from airflow.providers.standard.operators.empty import EmptyOperator
from airflow.providers.http.operators.http import HttpOperator
from airflow.providers.standard.operators.python import PythonOperator
import pandas as pd
from io import StringIO



def process_filter_ipv4(task_instance):
    # # Solution without xcom
    # df_solution1 = pd.read_csv('http://httpdata_nginx_intrusion/public_network_logs.csv')
    # Solution with xcom
    data = task_instance.xcom_pull(key='return_value', task_ids=['extract_dbip'])
    df = pd.read_csv(StringIO('\n'.join(data)), names=['ip_start_range', 'ip_end_range', 'country_code'])
    df_filtered = df[df['ip_start_range'].str.match(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')] #filter rows
    print(f'Before filter: {df.count()}, After filter: {df_filtered.count()}')
    return df_filtered

def process_filter_remove_col(task_instance):
    data = task_instance.xcom_pull(key='return_value', task_ids=['extract_pub_log'])
    df = pd.read_csv(StringIO('\n'.join(data)))
    # Source_IP,Destination_IP,Port,Request_Type,Protocol,Payload_Size,User_Agent,Status,Intrusion,Scan_Type
    # filter cols
    df_filtered = df[['Source_IP', 'Destination_IP', 'Port', 'Request_Type', 'Payload_Size', 'User_Agent', 'Status', 'Intrusion']]
    return df_filtered

def process_convert_ipv4(task_instance):
    df = task_instance.xcom_pull(key='return_value', task_ids=['filter_ipv4'])
    print(df[0:2])
    print(type(df))
    
def process_convert_ipv4_pub(task_instance):
    df = task_instance.xcom_pull(key='return_value', task_ids=['filter_remove_col'])
    print(df[0:2])
    print(type(df))

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
    map_ip_country = EmptyOperator(task_id='map_ip_country')
    load = EmptyOperator(task_id='load')
    
    extract_dbip >> filter_ipv4 >> convert_into_ipv4
    extract_pub_log >> filter_remove_col >> convert_into_ipv4_pub
    [convert_into_ipv4, convert_into_ipv4_pub] >> map_ip_country >> load