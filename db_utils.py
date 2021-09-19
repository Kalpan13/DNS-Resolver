import sqlite3
con = sqlite3.connect('DNS_Records.db')
cur = con.cursor()

# Create table
cur.execute('''CREATE TABLE Records
               (Host text, IP text, symbol text, qty real, price real)''')

# Insert a row of data
cur.execute("INSERT INTO stocks VALUES ('2006-01-05','BUY','RHAT',100,35.14)")

# Save (commit) the changes
con.commit()

con.close()