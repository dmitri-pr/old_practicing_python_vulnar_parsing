import urllib.error
from urllib.parse import urljoin
from urllib.parse import urlparse
from urllib.request import urlopen
from bs4 import BeautifulSoup
import ssl
import re
import sqlite3
import sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

conn = sqlite3.connect('kasper_vulnar.sqlite')
cur = conn.cursor()

cur.execute('''CREATE TABLE IF NOT EXISTS Products
    (id INTEGER NOT NULL PRIMARY KEY, product TEXT UNIQUE)''')

cur.execute('''CREATE TABLE IF NOT EXISTS Prod_to_kla
    (product_id INTEGER, vulnerabilities_id INTEGER, UNIQUE(product_id, vulnerabilities_id))''')

cur.execute('''CREATE TABLE IF NOT EXISTS Vulnerabilities
    (id INTEGER NOT NULL PRIMARY KEY, kasper_lab_id TEXT UNIQUE, vul_name TEXT UNIQUE)''')

cur.execute('''CREATE TABLE IF NOT EXISTS Kla_to_cve
    (vulnerabilities_id INTEGER, cve_ids_id INTEGER, UNIQUE(vulnerabilities_id, cve_ids_id))''')

cur.execute('''CREATE TABLE IF NOT EXISTS Cve_ids
    (id INTEGER NOT NULL PRIMARY KEY, cve_ids TEXT UNIQUE, cve_ids_link TEXT UNIQUE)''')

product = sys.argv[1]

cur.execute('SELECT id FROM Products WHERE product=? LIMIT 1', (product,))
row = cur.fetchone()
if row is not None:
    print("\nThis product already exists in the database. Enter another product name.\n")
    quit()

url = 'https://threats.kaspersky.com/en/vulnerability/'
document = urlopen(url, context=ctx)
html = document.read()

soup = BeautifulSoup(html, "html.parser")

info_line = soup.find(lambda tag: tag.name == 'tr' and tag.find(
    lambda ttag: ttag.name == 'td' and ttag.find(lambda tttag: tttag.name == 'a' and tttag.text.strip() == product)))

if info_line is None:
    print("\nLooks like incorrect entry - enter another product name.\n")
    quit()

product_info = info_line.find(
    lambda tag: tag.name == 'td' and tag.find('a', attrs={'class': 'gtm_vulnerabilities_vendor'}))
cur.execute('INSERT OR IGNORE INTO Products (product) VALUES ( ? )', (product,))

cur.execute('SELECT id FROM Products WHERE product=? LIMIT 1', (product,))
row = cur.fetchone()
products_id = row[0]

product_info_ = product_info.find(lambda tag: tag.name == 'a')
product_link = product_info_.get('href')
print('A link to information about product:', product_link, '\n\n')

url_1 = product_link
document = urlopen(url_1, context=ctx)
html_1 = document.read()

soup = BeautifulSoup(html_1, "html.parser")

tags_tr = soup.find_all('tr', attrs={'class': 'line_info line_info_vendor line_list2'})

for tags in tags_tr:
    tags_td = tags.find_all('td')
    kasper_lab_id = tags_td[0].text.strip()
    vul_link = tags_td[0].a.get('href')
    vul_name = tags_td[1].text.strip()

    cur.execute('INSERT OR IGNORE INTO Vulnerabilities (kasper_lab_id, vul_name) VALUES (?, ?)',
                (kasper_lab_id, vul_name))

    cur.execute('SELECT id FROM Vulnerabilities WHERE kasper_lab_id=? LIMIT 1', (kasper_lab_id,))
    row = cur.fetchone()
    vulnerabilities_id = row[0]

    cur.execute('INSERT OR IGNORE INTO Prod_to_kla (product_id, vulnerabilities_id) VALUES (?, ?)',
                (products_id, vulnerabilities_id))

    url_2 = vul_link
    document = urlopen(url_2, context=ctx)
    html_2 = document.read()

    soup = BeautifulSoup(html_2, "html.parser")

    tags_a_cve = soup.find_all('a', attrs={'class': 'gtm_vulnerabilities_cve'}, string=re.compile('CVE.+'))

    for tags in tags_a_cve:
        cve_ids = tags.text.strip()
        cve_ids_link = tags.get('href')
        print(cve_ids, '\n\n')
        print(cve_ids_link, '\n\n')

        cur.execute('INSERT OR IGNORE INTO Cve_ids (cve_ids, cve_ids_link) VALUES (?, ?)', (cve_ids, cve_ids_link))

        cur.execute('SELECT id FROM Cve_ids WHERE cve_ids=? LIMIT 1', (cve_ids,))
        row = cur.fetchone()
        cve_ids_id = row[0]

        cur.execute('INSERT OR IGNORE INTO Kla_to_cve (vulnerabilities_id, cve_ids_id) VALUES (?, ?)',
                    (vulnerabilities_id, cve_ids_id))

conn.commit()
cur.close()

# SELECT Products.product, Vulnerabilities.kasper_lab_id, Vulnerabilities.vul_name, Cve_ids.cve_ids, Cve_ids.cve_ids_link
# FROM Products
# JOIN Prod_to_kla on Products.id=Prod_to_kla.product_id
# JOIN Vulnerabilities on Vulnerabilities.id=Prod_to_kla.vulnerabilities_id
# JOIN Kla_to_cve on Vulnerabilities.id=Kla_to_cve.vulnerabilities_id
# JOIN Cve_ids on Cve_ids.id=Kla_to_cve.cve_ids_id
