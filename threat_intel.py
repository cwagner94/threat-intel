import requests
from pprint import pprint
import os
import re

VT_API_KEY = os.getenv('VT_API_KEY')


class File:
    def __init__(self, name, sha256, threat_score, reputation):
        self.name = name
        self.sha256 = sha256
        self.threat_score = threat_score
        self.reputation = reputation


class Domain:
    def __init__(self, url, threat_score, country):
        self.url = url
        self.threat_score = threat_score
        self.country = country


class IpAddress:
    def __init__(self, value, threat_score, country):
        self.value = value
        self.threat_score = threat_score
        self.country = country


def main():
    search_term = get_user_input()
    # search_term = "e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5"
    search_term = "134.23.1.5"
    if user_input_is_valid(search_term):
        ioc_category = get_ioc_category(search_term)
        pprint(get_vt_ioc(search_term, ioc_category))


def get_user_input():
    return input("Enter a Search Term: ")


def user_input_is_valid(user_input):
    if user_input:
        return True
    else:
        print('Invalid input. Please enter a search term')
        return False


def get_ioc_category(search_term):
    # TODO add regex for url matching
    if is_sha256(search_term) or is_md5(search_term):
        return 'files'
    if is_ipv4(search_term) or is_ipv6(search_term):
        return 'ip_addresses'


def is_sha256(search_term):
    sha256_regex = r"\b[a-f0-9]{64}\b"
    sha256_match = re.search(sha256_regex, search_term)
    if sha256_match:
        return True
    else:
        return False


def is_md5(search_term):
    md5_regex = r"\b[a-f0-9]{32}\b"
    md5_match = re.search(md5_regex, search_term)
    if md5_match:
        return True
    else:
        return False


def is_ipv4(search_term):
    ipv4_regex = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    ipv4_match = re.search(ipv4_regex, search_term)
    if ipv4_match:
        return True
    else:
        return False


def is_ipv6(search_term):
    ipv6_regex = r"\b(?:[a-f0-9]{1,4}:){1,7}[a-f0-9]{1,4}|\b::(?:[a-f0-9]{1,4}:){0,6}[a-f0-9]{1,4}\b"
    ipv6_match = re.search(ipv6_regex, search_term)
    if ipv6_match:
        return True
    else:
        return False


def get_vt_ioc(id, field):
    url = f"https://www.virustotal.com/api/v3/{field}/{id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.text


if __name__ == "__main__":
    main()


# TODO Add requirements.txt
