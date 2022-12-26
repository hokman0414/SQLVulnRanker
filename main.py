import mysql.connector
import keyring
import subprocess
import csv
#run seperate script
cmd='python Vulnextractor.py'
proc =subprocess.Popen(cmd,shell=True)
#wait until script finish running before resuming main.py
proc.wait()

#run vulnranker
cmd2='python vulnranker.py'
proc=subprocess.Popen(cmd2,shell=True)
proc.wait()



#make sure to use pip3 install mysql-connector-python (don't use pip or else it will give authentication error)
#get credentials with keyring
x = keyring.get_credential(service_name="mysql",username=None)

username = x.username
#print(username)
password =x.password
#print(password)
#print(username)
#print(password)

#login to sql server
mydb= mysql.connector.connect(
    host="127.0.0.1",
    user=username,
    passwd=password,
#point to database when connecting (optional)
    database="siemdb"

)
#creating database and table inside
#must create a selector first
mycursor=mydb.cursor()
#create database and add sql queries
#mycursor.execute("CREATE DATABASE SIEMDB")

#list db
#mycursor.execute("SHOW DATABASES")
#for db in mycursor:
    #print(db)
#drop the cve table then create again
mycursor.execute("DROP TABLE cvetable")

#crerate table in SQL (label variable inside)
mycursor.execute("CREATE TABLE cvetable (cvename VARCHAR(255),date_published VARCHAR(50), date_modified VARCHAR(50), Nvd_link VARCHAR(255),Description TEXT)")
mycursor.execute("ALTER TABLE cvetable ADD PRIMARY KEY (cvename)")

#list tables
#mycursor.execute("SHOW TABLES")
#for i in mycursor:
    #print(i)

#populate data from csv file

with open('CVEVulnTracker.csv', 'r') as file:
    # Create a CSV reader object
    reader = csv.reader(file)

    # Iterate over the rows in the file
    for cve in reader:
        #get CVE
        #add values into table
        cve_values= tuple(cve)

        #insert to table
        sqlFormula = "INSERT INTO cvetable VALUES (%s, %s,%s,%s,%s)"
        mycursor.execute(sqlFormula, cve_values)
        # confirm add data
        mydb.commit()

# Select all rows from the cvetable table
mycursor.execute("SELECT * FROM cvetable")

# Iterate over the rows and print the values
for row in mycursor:
    print(row)






#insert sample code
'''
sqlFormula="INSERT INTO cvetable VALUES (%s, %s,%s,%s,%s)"
#example = ("T1","T1","T1","T1","T1")
mycursor.execute(sqlFormula,example)
#confirm add data
mydb.commit()
'''


