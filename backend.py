# app.py (Flask backend)
from flask import Flask, request, jsonify
import skops.io as sio
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn import svm
from sklearn.metrics import precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from urllib.parse import urlparse, urlencode
import ipaddress
import re

unknown_types = sio.get_untrusted_types(file='full_randomforest.skops')
clf = sio.load('full_randomforest.skops', trusted=unknown_types)

app = Flask(__name__)

# Implement your phishing detection logic using your machine learning model
# Replace the dummy logic below with your actual detection code
def detect_phishing(data):
    print(data['url'])
    
    X = np.array(extract_features(data['url'])[1:]).reshape(1,-1)
    clf.predict(X)
    print(X)
    
    phishing_likelihood = 1.0
    return {'phishing_likelihood': phishing_likelihood}

@app.route('/', methods=['GET'])
def home():
    return 'Phishing Detector Backend'

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    result = detect_phishing(data)
    return jsonify(result)

def extract_domain(url):
    domain = urlparse(url).netloc # for example netloc = www.google.com

    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "") # Ex: transform www.google.com ---> google.com

    return domain

def ip_address_present(url):
    # find a list of ipv4 addresses
    ipv4 = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)

    # find a list of ipv6 addresses
    ipv6 = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}.\d{1,3}', url)

    if len(ipv4) == 0 and len(ipv6) == 0:
        return 0
    else:
        return 1

def at_symbol_present(url):
    if "@" in url:
        return 1
    else:
        return 0
    
def count_subdomain(url):
    
    # get the hostname/domain
    hostname = extract_domain(url)

    # print(hostname)

    # get the number of subdomains
    subdomain_count = hostname.count('.')

    if subdomain_count > 3:
        return 1
    else:
        return 0
  
# Source: https://link.springer.com/article/10.1007/s40745-022-00379-8
def url_length(url):
    if len(url) < 75:
        return 0
    else:
        return 1
    
def get_url_depth(url):
    
    s = urlparse(url).path.split('/')
    count = 0

    for j in range(len(s)):
        if len(s[j]) != 0:
            count += 1

    return count

def redirection(url):
    
    double_slash = re.findall('//', url)

    if len(double_slash) > 1:
        return 1
    else:
        return 0

def https_in_domain(url):
    
    # get the domain name
    # domain = urlparse(url).netloc
    domain = url

    if 'https' in domain:
        return 1
    else:
        return 0
    
def dash_present(url):
    
    domain = urlparse(url).netloc

    if '-' in domain:
        return 1
    else:
        return 0

def extract_features(url):
    
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
               dash_present
              ]

  for f in functions:
    features.append( f(url) )

  return features


if __name__ == '__main__':
    app.run(debug=True)
