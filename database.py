import psycopg2
from psycopg2 import sql
from psycopg2.extras import DictCursor

def connect_to_database():
    return psycopg2.connect(
        host="localhost",
        database="postgres",
        user="postgres",
        password="shriji12",
        port="5432"
    )

def execute_query(query, params=None, fetchall=False, fetchone=False):
    connection = connect_to_database()
    cursor = connection.cursor(cursor_factory=DictCursor)

    try:
        if params:
            print("Executing Query:", cursor.mogrify(query, params))
            cursor.execute(query, params)
        else:
            print("Executing Query:", cursor.mogrify(query))
            cursor.execute(query)

        if fetchall:
            result = cursor.fetchall()
        elif fetchone:
            result = cursor.fetchone()
        else:
            result = None

        connection.commit()
        return result

    except Exception as e:
        print("Error executing query:", e)
        return None

    finally:
        cursor.close()
        connection.close()