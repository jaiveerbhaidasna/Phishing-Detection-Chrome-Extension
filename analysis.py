# -*- coding: utf-8 -*-

# Commented out IPython magic to ensure Python compatibility.
# %pip install python-whois
# %pip install gdown

print("Hello, World!")

import whois

from datetime import datetime

def get_domain_age(domain_name):
    try:
        w = whois.whois(domain_name)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        current_date = datetime.now()
        age = (current_date - creation_date).days
        return age
    except Exception as e:
        print(f"Error: {e}")
        return None

# Example usage
domain_name = "	https://odaddy.best/" # phising site
age = get_domain_age(domain_name)
if age:
    print(f"The domain {domain_name} is {age} days old.")

domain_name_2 = "www.google.com"
age = get_domain_age(domain_name_2)
if age:
    print(f"The domain {domain_name_2} is {age} days old.")

"""## 1. Dataset preparation

1. Positive samples (Phishing URLs)

2. Negative samples (Non-phishing URLs)

(New) 3. Hard negative samples (Non-phishing URLs)

Use scrapy to craw more detailed URLs to construct a harder dataset

### 1.1 Data preprocessing

#### 1.1.1 Easy non-phishing URLs
"""

!pip install httpx

import pandas as pd
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
import httpx

N = 500

'''Phishing URLs from Openphish'''
!gdown https://drive.google.com/uc?id=1-F7FjGHbecHwO-T1SRx21RlpGx3B8wEA

with open('/content/openphish.com_feed.txt', 'r') as f:
  data = f.readlines()
  data = [d.strip() for d in data]
df1 = pd.DataFrame({'URL':data})
df1['Label'] = 'Phishing'
df1

'''Non-phishing URLs from Tranco'''
# !gdown 1bsIJxzpNzPeG3VR-IWiWclN_jOrj16b5
!gdown 1x3HEbBpR-qzI-YQXJAiHjAav3jZ667ZG

# df2 = pd.read_csv('/content/tranco_LYLJ4.csv', header=None)
df2 = pd.read_csv('/content/tranco_Z257G.csv', header=None)
df2 = df2.rename(columns={1:'Domain'}).head(2*N)[['Domain']]
df2['Label'] = 'Non-phishing'
df2

def crawl_domain(domain):
    # Try HTTPS first
    https_url = 'https://' + domain
    http_url = 'http://' + domain
    url_to_use = https_url
    timeout_length = 3  # Set timeout to 3 seconds

    try:
        # Fetch content from domain with HTTPS
        response = requests.get(https_url, timeout=timeout_length)
        response.raise_for_status()
    except requests.RequestException:
        # If HTTPS fails, try HTTP
        try:
            response = requests.get(http_url, timeout=timeout_length)
            response.raise_for_status()
            url_to_use = http_url
        except requests.RequestException as e:
            print(f"Error fetching {domain} with both HTTPS and HTTP: {e}")
            return []

    # Parse the HTML content
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all links
    links = soup.find_all('a')

    # Extract URLs and filter them
    urls = [link.get('href') for link in links if link.get('href') and url_to_use in link.get('href')]

    return urls

def check_protocol(domain):
    https_url = f'https://{domain}'
    http_url = f'http://{domain}'
    timeout_length = 5

    try:
        # Try connecting with HTTPS
        response = httpx.get(https_url, follow_redirects=True,timeout=timeout_length)
        if response.is_success:
            return https_url # 'HTTPS'
    except httpx.RequestError:
        pass

    try:
        # Fall back to HTTP
        response = httpx.get(http_url, follow_redirects=True,timeout=timeout_length)
        if response.is_success:
            return http_url # 'HTTP'
    except httpx.RequestError:
        pass

    return '' # 'Neither HTTP nor HTTPS'

# Example usage
domain_name = 'google.com'
protocol = check_protocol(domain_name)
print(f'{domain_name} uses {protocol}')

url_list = []
for domain in tqdm(df2.Domain.unique().tolist()):

  try:
    url = check_protocol(domain)
    url_list.append(url)
  except:
    url_list.append('')

df2['URL'] = url_list
df2

df2 = df2[~(df2.URL=='Neither HTTP nor HTTPS')]
df2

df2['URL'] =df2.apply(lambda row: row['URL'].lower()+'://'+row['Domain'], axis=1)
df2 = df2[['URL', 'Label']]
df2

df2 = df2[df2.URL.str.contains('http')]
df2

df = pd.concat([df1, df2.head(N)], ignore_index=True) # For combining positive and negative samples, we may want to add https:// to every non-phishing website to avoid overfitting.
df

df.to_csv('/content/full.csv')

"""#### 1.1.2 Hard non-phishing URLs"""

!pip install requests bs4
!pip install scrapy

from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor

class Crawler(CrawlSpider):
    name = 'imdb'
    allowed_domains = ['www.imdb.com']
    start_urls = ['https://www.imdb.com/']
    rules = (Rule(LinkExtractor()),)

!scrapy startproject scrapy_crawler

!scrapy

!scrapy crawl imdb --logfile imdb.log

df3 = df[df.Label=='Non-phishing']
df3

Crawler(urls=['https://google.com']).run()







"""### 1.2 Load processed dataset"""

import pandas as pd

df = pd.read_csv('/content/full.csv', index_col=0)
df

df.tail(10)

"""## 2. Feature Extractions:

State of the art features:
1. Domain age
2. Domain
3. URL Length

New features:
1. SSL

### Domain
"""

from urllib.parse import urlparse, urlencode
import ipaddress
import re

# Extract the domain from the url
def extract_domain(url):
  domain = urlparse(url).netloc # for example netloc = www.google.com

  if re.match(r"^www.", domain):
    domain = domain.replace("www.", "") # Ex: transform www.google.com ---> google.com

  return domain

link = "http://www.google.com"
host = extract_domain(link)
host

"""### Domain age"""

# Max age of phishing domains: 1 year = 365 days
def extract_domain_age(url):

  try:
    # get the domain
    domain = urlparse(url).netloc # for example netloc = www.google.com

    # get the domain age
    domain_age = get_domain_age(domain)

    if domain_age < 365:
      return 1
    else:
      return 0
  except:
    return -1

"""### Presence of an IP address"""

def ip_address_present(url):
  # find a list of ipv4 addresses
  ipv4 = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)

  # find a list of ipv6 addresses
  ipv6 = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}', url)

  if len(ipv4) == 0 and len(ipv6) == 0:
    return 0
  else:
    return 1

"""### Presence of "@" in url"""

def at_symbol_present(url):
  if "@" in url:
    return 1
  else:
    return 0

"""### Number of dots in the domain name (Essentially using a lot of subdomains)"""

def count_subdomain(url):

  # get the hostname/domain
  hostname = extract_domain(url)

  print(hostname)

  # get the number of subdomains
  subdomain_count = hostname.count('.')

  if subdomain_count > 3:
    return 1
  else:
    return 0

"""### Length of the url"""

# Source: https://link.springer.com/article/10.1007/s40745-022-00379-8
def url_length(url):
  if len(url) < 75:
    return 0
  else:
    return 1

"""### Depth of URL: Number of subpages"""

def get_url_depth(url):

  s = urlparse(url).path.split('/')
  count = 0

  for j in range(len(s)):
    if len(s[j]) != 0:
      count += 1

  return count

"""### Redirection: Presence of '//' in the URL besides after http and https"""

def redirection(url):

  double_slash = re.findall('//', url)

  if len(double_slash) > 1:
    return 1
  else:
    return 0

"""### HTTPS in domain name"""

def https_in_domain(url):

  # get the domain name
  # domain = urlparse(url).netloc
  domain = url

  if 'https' in domain:
    return 1
  else:
    return 0

"""### Presence of dash '-'"""

def dash_present(url):

  domain = urlparse(url).netloc

  if '-' in domain:
    return 1
  else:
    return 0

"""### SSL certificate information"""

!pip install pyOpenSSL

from OpenSSL import SSL
import cryptography
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna

from socket import socket
from collections import namedtuple
import datetime

!pip install wrapt_timeout_decorator

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')

from wrapt_timeout_decorator import timeout
@timeout(3, timeout_exception=TimeoutError)
def get_certificate(hostname, port):
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

# get the certificate for a phishing website
hostinfo = get_certificate('web3secure.net.cryptobackupaid.com', 443)
cert = hostinfo.cert
expiry = cert.not_valid_after

current_time = datetime.datetime.utcnow()
print(expiry)
print(current_time)

if (current_time > expiry):
  print('Cert has expired!')
else:
  print('Cert is valid!')

cert.issuer

cert.signature_hash_algorithm

"""### get the certificate validity period in days

"""

def get_cert_validity(url):

  try:
    # get the domain name
    domain_name = extract_domain(url)

    hostinfo = get_certificate(domain_name, 443)
    cert = hostinfo.cert
    issue = cert.not_valid_before
    expiry = cert.not_valid_after

    validity = expiry - issue
    return validity.days
  except:
    return -1

"""### check certificate expiry"""

def cert_expired(url):

  try:
    # get the domain name
    domain_name = extract_domain(url)

    hostinfo = get_certificate(domain_name, 443)
    cert = hostinfo.cert
    expiry = cert.not_valid_after

    current_time = datetime.datetime.utcnow()

    if (current_time > expiry):
      return 1
    else:
      return 0
  except:
    return -1

"""### cert hash algorithm"""

def hash_md5(url):

  try:
    # get the domain name
    domain_name = extract_domain(url)
    # print(domain_name)

    hostinfo = get_certificate(domain_name, 443)
    cert = hostinfo.cert

    # print(cert.signature_hash_algorithm)

    if type(cert.signature_hash_algorithm) == cryptography.hazmat.primitives.hashes.MD5:
      return 1
    else:
      return 0
  except:
    return -1

hash_md5('http://web3secure.net.cryptobackupaid.com')

"""## 3. Getting all Features

### Return a list of features per url
"""

def extract_features(url, label):

  features = []

  functions = [
               extract_domain,
              #  extract_domain_age,
               ip_address_present,
               at_symbol_present,
               count_subdomain,
               url_length,
               get_url_depth,
               redirection,
               https_in_domain,
               dash_present,
               get_cert_validity,
               cert_expired,
               hash_md5
              ]

  for f in functions:
    features.append( f(url) )

  if label == 'Phishing':
    features.append(1)
  else:
    features.append(0)

  return features

link = 'https://www.google.com'

extract_features(link, 'Phishing')

extract_features('https://clients3.google.com', 'Phishing')

"""## Create Dataset"""

data = []

for index, row in df.iterrows():
    # print(row['URL'], row['Label'])

    data.append( extract_features( row['URL'], row['Label'] ) )

columns = [
    "domain name",
    "ip_address_present",
    "at_symbol_present",
    "count_subdomain",
    "url_length",
    "get_url_depth",
    "redirection",
    "https_in_domain",
    "dash_present",
    "certificate validity period",
    "cert_expired",
    "cert_hash_md5",
    "Label"
]

dataset = pd.DataFrame(data, columns=columns)

dataset

dataset[dataset.Label==1].dash_present.value_counts()

# dataset.to_csv('/content/full_dataset.csv')
dataset.to_csv('/content/full_wssl_dataset.csv')

# Commented out IPython magic to ensure Python compatibility.
# %pip install dill

import dill

with open(dill_file, 'rb') as f:
        pickleData=dill.load( f )
        train_x,train_y=pickleData["train_x"],pickleData["train_y"]
        val_x,val_y=pickleData["val_x"],pickleData["val_y"]
        test_x,test_y=pickleData["test_x"],pickleData["test_y"]
        char_to_int=pickleData["char_to_int"]

"""## 4. ML model training

### 4.1 Non-DL model

1. Random forest
2. Gradient boosting tree
3. Support vector machine
"""

from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn import svm
from sklearn.metrics import precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score

X = dataset[dataset.columns[1:-1]].values
y = dataset['Label'].values
X.shape, y.shape

'''split train,test set'''

clf = RandomForestClassifier(random_state=0)
clf.fit(X[200:800], y[200:800])
clf.predict(X[100:200])

'''Random forest classifier'''

clf = RandomForestClassifier(random_state=0)
scores = cross_val_score(clf, X, y, cv=5, scoring='recall')
scores.mean(), scores.std()

'''Gradient boosting classifier'''

clf = GradientBoostingClassifier(random_state=2)
scores = cross_val_score(clf, X, y, cv=5, scoring='precision')
scores.mean(), scores.std()

'''svm'''

clf = svm.SVC(kernel='linear', C=1, random_state=42)
scores = cross_val_score(clf, X, y, cv=5, scoring='recall')
scores.mean(), scores.std()

clf = RandomForestClassifier(random_state=0)
clf.fit(X, y)
clf.predict(X).sum()

!pip install skops

import skops.io as sio
# sio.dump(clf, 'full_randomforest.skops')
sio.dump(clf, 'full_wssl_randomforest.skops')

"""### 4.2 Load trained models"""

# !gdown 1JlGi-enFKx_5rC5izapAlVNps4tnDN2h
!gdown 1s6fYJzY943dazk7P7G9-rpNIneKO9fE5

# clf = sio.load('full_randomforest.skops')
clf = sio.load('full_wssl_randomforest.skops')
clf.predict(X).sum()

import numpy as np

"""#### 4.2.1 Openphish"""

X_test = np.array(extract_features('https://link-9848.dana-id.biz/kaget', 'Phishing')[1:-1]).reshape(1,-1)
clf.predict(X_test)

X_test = np.array(extract_features('https://arstmping002.firebaseapp.com/', 'Phishing')[1:-1]).reshape(1,-1)
clf.predict(X_test)

X_test = np.array(extract_features('http://www.casino-met-paypal.com/', 'Phishing')[1:-1]).reshape(1,-1)
clf.predict(X_test)

"""#### 4.2.2 Phish tank"""

X_test = np.array(extract_features('http://web3secure.net.cryptobackupaid.com', 'Phishing')[1:-1]).reshape(1,-1)
clf.predict(X_test)

X_test = np.array(extract_features('https://mynumbercardpoint-sounu-jp.com/', 'Phishing')[1:-1]).reshape(1,-1)
clf.predict(X_test)

X_test = np.array(extract_features('https://mailbox-oii909889.weeblysite.com/', 'Phishing')[1:-1]).reshape(1,-1)
clf.predict(X_test)

"""#### 4.2.3 Normal non-phishing websites"""

X_test = np.array(extract_features('https://gatech.edu', 'Non-Phishing')[1:-1]).reshape(1,-1)
clf.predict(X_test)

X_test = np.array(extract_features('https://chat.openai.com/', 'Non-Phishing')[1:-1]).reshape(1,-1)
clf.predict(X_test)

X_test = np.array(extract_features('https://scikit-learn.org', 'Non-Phishing')[1:-1]).reshape(1,-1)
clf.predict(X_test)

y_pred = clf.predict(X)
mask = y != y_pred
mask.shape

mask.sum()

"""#### Some misclassified examples from OpenPhish and Non-phishing URLs"""

for idx in np.where(mask)[0]:
    url = df.loc[idx]['URL']
    print(url)
    print(X[idx])
    print('Ground truth:', y[idx])
    X_test = np.array(extract_features(url, df.loc[idx]['Label'])[1:-1]).reshape(1,-1)
    y_pred = clf.predict(X_test)
    print('Predicted:', y_pred[0])

