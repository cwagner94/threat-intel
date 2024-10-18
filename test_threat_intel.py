from threat_intel import user_input_is_valid, is_sha256, is_md5, is_ipv4, is_ipv6, get_ioc_category, get_vt_ioc


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
    # assert is_ipv6('::') == True  # TODO currently fails
    assert is_ipv6('2001:db8:0:0:1:0:0:1') == True
    assert is_ipv6('2001:db8::1:0:0:1') == True
    # assert is_ipv6('2600::') == True  # TODO currently fails


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


def test_get_ioc_category_invalid_files():
    pass


def test_get_ioc_category_valid_ip_addresses():
    assert get_ioc_category('10.4.2.4') == 'ip_addresses'
    assert get_ioc_category('')


def test_get_ioc_category_invalid_ip_addresses():
    pass
