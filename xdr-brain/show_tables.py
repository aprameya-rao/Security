from clickhouse_driver import Client

# Connect to ClickHouse
client = Client(host='localhost', user='default', password='admin')

# Ask the database to list all tables
tables = client.execute('SHOW TABLES')

print("\n[*] Connected Successfully!")
print(f"[*] Tables found in your database: {tables}\n")
