import psycopg2

conn = psycopg2.connect(
    host="dpg-d9adtslaeets73dlraeg-a.oregon-postgres.render.com",
    port=5432,
    dbname="nfies_db_75je",
    user="nfies_db_75je_user",
    password="hfkR7lX5Nr11midzqOcJ9e0IC4Xc2GnI",
)
cur = conn.cursor()

cur.execute("SELECT * FROM alembic_version;")
print("alembic_version:", cur.fetchall())

cur.close()
conn.close()
