from unittest import mock
from threat_intel import user_input_is_valid, is_sha256, is_md5, is_ipv4, is_ipv6, get_ioc_category, get_vt_ioc, is_filename, is_domain, is_url
import pytest


def test_user_input_is_valid_no_input():
    assert user_input_is_valid('') == False


def test_user_input_is_valid_standard_string():
    assert user_input_is_valid('this is a string') == True


def test_is_sha256_valid_sha256_hash():
    assert is_sha256(
        'e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5') == True


def test_is_sha256_invalid_sha256_hash():
    assert is_sha256('938c2cc0dcc05f2b68c4287040cfcf71') == False
    assert is_sha256('294.234.55.2') == False
    assert is_sha256('') == False


def test_is_md5_valid_md5_hash():
    assert is_md5('938c2cc0dcc05f2b68c4287040cfcf71') == True


def test_is_md5_invalid_md5_hash():
    assert is_md5(
        'e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5') == False
    assert is_md5('294.234.55.2') == False
    assert is_md5('') == False


def test_is_ipv4_valid_ipv4():
    assert is_ipv4('135.3.1.55') == True
    assert is_ipv4('0.0.0.0') == True
    assert is_ipv4('232.12.45.1') == True


def test_is_ipv4_invalid_ipv4():
    assert is_ipv4('2,3.4.13') == False
    assert is_ipv4('938c2cc0dcc05f2b68c4287040cfcf71') == False
    assert is_ipv4('2001:db8:3333:4444:5555:6666:7777:8888:') == False


def test_is_ipv6_valid_ipv6():
    assert is_ipv6('2001:db8:3333:4444:5555:6666:7777:8888:') == True
    assert is_ipv6('2001:db8:0:0:1:0:0:1') == True
    assert is_ipv6('2001:db8::1:0:0:1') == True
    # assert is_ipv6('2600::') == True  # TODO currently fails
    # assert is_ipv6('::') == True  # TODO currently fails


def test_is_ipv6_invalid_ipv6():
    assert is_ipv6('135.3.1.55') == False
    assert is_ipv6('0.0.0.0') == False
    assert is_ipv6('232.12.45.1') == False
    assert is_ipv6('sentence:with:colonsinit') == False


def test_get_ioc_category_valid_files():
    assert get_ioc_category(
        'e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5') == 'files'
    assert get_ioc_category('938c2cc0dcc05f2b68c4287040cfcf71') == 'files'
    assert get_ioc_category('filename.bat') == 'files'
    assert get_ioc_category('otherfile.sh') == 'files'


def test_get_ioc_category_valid_ip_addresses():
    assert get_ioc_category('10.4.2.4') == 'ip_addresses'
    assert get_ioc_category(
        '2001:db8:3333:4444:5555:6666:7777:8888:') == 'ip_addresses'
    assert get_ioc_category('0.0.0.0') == 'ip_addresses'
    assert get_ioc_category('2001:db8::1:0:0:1') == 'ip_addresses'
    assert get_ioc_category('10.3.45.10') != 'files'


# def test_get_ioc_category_valid_domain():
#     assert get_ioc_category('google.com') == 'domains'
#     assert get_ioc_category('google.org') == 'domains'
#     assert get_ioc_category('google.net') == 'domains'
#     assert get_ioc_category('google.edu') == 'domains'
#     assert get_ioc_category('google.top') == 'domains'
#     assert get_ioc_category('google.xyz') == 'domains'


# def test_get_ioc_category_valid_url():
#     assert get_ioc_category('www.google.com') == 'urls'
#     assert get_ioc_category('http://www.google.com') == 'urls'
#     assert get_ioc_category('https://www.google.com') == 'urls'
#     assert get_ioc_category('www.google.org') == 'urls'
#     assert get_ioc_category('http://www.google.org') == 'urls'
#     assert get_ioc_category('https://www.google.org') == 'urls'
#     assert get_ioc_category('www.google.net') == 'urls'
#     assert get_ioc_category('http://www.google.net') == 'urls'
#     assert get_ioc_category('https://www.google.net') == 'urls'
#     assert get_ioc_category('www.google.edu') == 'urls'
#     assert get_ioc_category('http://www.google.edu') == 'urls'
#     assert get_ioc_category('https://www.google.edu') == 'urls'
#     assert get_ioc_category('http://www.google.top') == 'urls'
#     assert get_ioc_category('https://www.google.top') == 'urls'
#     assert get_ioc_category('www.google.xyz') == 'urls'
#     assert get_ioc_category('http://www.google.xyz') == 'urls'
#     assert get_ioc_category('https://www.google.xyz') == 'urls'


def test_is_filename_valid():
    assert is_filename('house.bat') == True
    assert is_filename('house.sh') == True
    assert is_filename('house.pdf.exe') == True


def test_is_filename_invalid():
    assert is_filename('10.5.23.44') == False
    assert is_filename('blahbal.10') == False
    assert is_filename('hello.x') == False
    assert is_filename('2001:db8:3333:4444:5555:6666:7777:8888:') == False


def test_get_vt_ioc_sha256():
    response = get_vt_ioc(
        'e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5', 'files')
    assert response.status_code == 200


def test_vt_ioc_md5():
    response = get_vt_ioc(
        '938c2cc0dcc05f2b68c4287040cfcf71', 'files')
    assert response.status_code == 200


def test_get_vt_ioc_ipv4():
    response = get_vt_ioc(
        '23.4.1.43', 'ip_addresses')
    assert response.status_code == 200


def test_get_vt_ioc_ipv6():
    response = get_vt_ioc(
        '2001:db8:3333:4444:5555:6666:7777:8888', 'ip_addresses')
    assert response.status_code == 200


# def test_get_vt_ioc_filename():
#     response = get_vt_ioc(
#         'powershell.exe', 'files')
#     assert response.status_code == 200


# def test_get_vt_ioc_filename():
#     response = get_vt_ioc(
#         'file.sh', 'files')
#     assert response.status_code == 200


# def test_get_vt_ioc_filename():
#     response = get_vt_ioc(
#         'update.js', 'files')
#     assert response.status_code == 200


# def test_get_vt_ioc_url():
#     response = get_vt_ioc(
#         'https://www.google.com', 'urls')
#     assert response.status_code == 200


# def test_get_vt_ioc_domain():
#     response = get_vt_ioc(
#         'google.com', 'domains')
#     assert response.status_code == 200


def test_get_vt_ioc_error_handling(mocker):
    mocker.patch('requests.get', return_value=mocker.Mock(status_code=404))

    with pytest.raises(Exception) as exception:
        get_vt_ioc('', 'ip_addresses')

    assert "Request failed with status code 404" in str(exception.value)


def test_is_domain():
    pass


def test_is_url():
    pass
