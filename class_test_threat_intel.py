from unittest import mock
from threat_intel import UserInput, Ioc, VirusTotal
import pytest


class TestUserInput:
    def test_get_user_input(self, monkeypatch):
        monkeypatch.setattr('builtins.input', lambda _: "This is a string")
        UserInput.get_user_input(self)
        assert self.user_input == "This is a string"

    def test_validate_no_input(self):
        self.user_input = ''
        UserInput.validate(self)
        assert self.valid == False

    def test_validate_standard_string(self):
        self.user_input = 'this is a string'
        UserInput.validate(self)
        assert self.valid == True


# class TestVirusTotal:
#     @pytest.mark.parametrize("params, expected_status", [
#         ({"ioc": '193.42.2.4', "category": "ip_addresses"}, 200),
#         ({"ioc": '193.42.2.4', "category": "files"}, 404)
#     ])
#     def test_get_api_response_200_status(self, mocker, params, expected_status):
#         mocker.patch.object('os.getenv', return_value='mock_api_key')
#         mocker.patch.object('threat_intel.VirusTotal.get_api_response',
#                             return_value=mocker.Mock(status_code=expected_status))

#         result = VirusTotal.get_api_response(self, params)
#         assert result.status_code == expected_status

    # def test_get_api_response_404_status(self, mocker, params, expected_status):
    #     mocker.patch('os.getenv', return_value='mock_api_key')
    #     mocker.patch('threat_intel.VirusTotal.get_api_response',
    #                  return_value=mocker.Mock(status_code=expected_status))

    #     result = VirusTotal.get_api_response(self, params)
    #     assert result.status_code == 404

    # def test_get_api_response_404_error_message(self, mocker):
    #     mocker.patch('os.getenv', return_value='mock_api_key')
    #     mocker.patch('threat_intel.VirusTotal.get_api_response',
    #                  side_effect=Exception('mocked error'))
    #     mocker.patch('threat_intel.VirusTotal.get_api_response',
    #                  return_value=mocker.Mock(status_code=404))
    #     with pytest.raises(Exception) as exception:
    #         VirusTotal.get_api_response(self)

    #     assert exception.value.message == 'mocked error'
    #     # assert "Request failed with status code 404" in str(exception.value)

    # def test_get_vt_ioc_sha256():
#     response = get_vt_ioc(
#         'e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5', 'files')
#     assert response.status_code == 200


# def test_vt_ioc_md5():
#     response = get_vt_ioc(
#         '938c2cc0dcc05f2b68c4287040cfcf71', 'files')
#     assert response.status_code == 200


# def test_get_vt_ioc_ipv4():
#     response = get_vt_ioc(
#         '23.4.1.43', 'ip_addresses')
#     assert response.status_code == 200


# def test_get_vt_ioc_ipv6():
#     response = get_vt_ioc(
#         '2001:db8:3333:4444:5555:6666:7777:8888', 'ip_addresses')
#     assert response.status_code == 200


# # def test_get_vt_ioc_filename():
# #     response = get_vt_ioc(
# #         'powershell.exe', 'files')
# #     assert response.status_code == 200


# # def test_get_vt_ioc_filename():
# #     response = get_vt_ioc(
# #         'file.sh', 'files')
# #     assert response.status_code == 200


# # def test_get_vt_ioc_filename():
# #     response = get_vt_ioc(
# #         'update.js', 'files')
# #     assert response.status_code == 200


# # def test_get_vt_ioc_url():
# #     response = get_vt_ioc(
# #         'https://www.google.com', 'urls')
# #     assert response.status_code == 200


# # def test_get_vt_ioc_domain():
# #     response = get_vt_ioc(
# #         'google.com', 'domains')
# #     assert response.status_code == 200


# def test_get_vt_ioc_error_handling(mocker):
#     mocker.patch('requests.get', return_value=mocker.Mock(status_code=404))

#     with pytest.raises(Exception) as exception:
#         get_vt_ioc('', 'ip_addresses')

#     assert "Request failed with status code 404" in str(exception.value)


class TestIoc:
    @pytest.mark.parametrize('value, expected', [
        ('house.bat', 'filename'),
        ('house.sh', 'filename'),
        ('house.pdf.exe', 'filename')
    ])
    def test_is_filename_valid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_filename()
        assert ioc.ioc_type == expected

    def test_is_sha256_valid(self):
        ioc = Ioc(
            'e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5')
        ioc.is_sha256()
        assert ioc.ioc_type == 'sha256'

    def test_is_md5_valid(self):
        ioc = Ioc('938c2cc0dcc05f2b68c4287040cfcf71')
        ioc.is_md5()
        assert ioc.ioc_type == 'md5'

    @pytest.mark.parametrize('value, expected', [
        ('132.5.5.12', 'ipv4'),
        ('0.0.0.0', 'ipv4'),
        ('232.12.45.1', 'ipv4')
    ])
    def test_is_ipv4_valid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_ipv4()
        assert ioc.ioc_type == expected

    @pytest.mark.parametrize('value, expected', [
        ('2001:db8:3333:4444:5555:6666:7777:8888:', 'ipv6'),
        ('2001:db8:0:0:1:0:0:1', 'ipv6'),
        ('2001:db8::1:0:0:1', 'ipv6')
        # ('2600::', 'ipv6'), # TODO currently fails
        # ('::', 'ipv6') # TODO currently fails
    ])
    def test_is_ipv6_valid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_ipv6()
        assert ioc.ioc_type == expected

    @pytest.mark.parametrize('value, expected', [
        ('https://www.google.com/', 'url'),
        ('http://www.google.com', 'url'),
        ('http://www.google.org', 'url'),
        ('https://www.google.io', 'url'),
        ('http://www.google.ru', 'url')
    ])
    def test_is_url_valid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_url()
        assert ioc.ioc_type == expected

    @pytest.mark.parametrize('value, expected', [
        ('google.com', 'domain'),
        ('google.ru', 'domain'),
        ('somewebsite.xyz', 'domain'),
        ('addiferentwebsite.org', 'domain'),
        ('whoami.io', 'domain')
    ])
    def test_is_domain_valid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_domain()
        assert ioc.ioc_type == expected

    # test is_* functions with invalid inputs

    def test_set_category(self):
        pass

    # def test_is_sha256_invalid_sha256_hash(self):
    #     self.ioc = '123.324.1.3'
    #     Ioc.is_md5(self)
    #     assert self.ioc_type != 'sha256'


# def test_is_md5_invalid_md5_hash():
#     assert is_md5(
#         'e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5') == False
#     assert is_md5('294.234.55.2') == False
#     assert is_md5('') == False


# def test_is_ipv4_invalid_ipv4():
#     assert is_ipv4('2,3.4.13') == False
#     assert is_ipv4('938c2cc0dcc05f2b68c4287040cfcf71') == False
#     assert is_ipv4('2001:db8:3333:4444:5555:6666:7777:8888:') == False


# def test_is_ipv6_invalid_ipv6():
#     assert is_ipv6('135.3.1.55') == False
#     assert is_ipv6('0.0.0.0') == False
#     assert is_ipv6('232.12.45.1') == False
#     assert is_ipv6('sentence:with:colonsinit') == False


# def test_get_ioc_category_valid_files():
#     assert get_ioc_category(
#         'e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5') == 'files'
#     assert get_ioc_category('938c2cc0dcc05f2b68c4287040cfcf71') == 'files'
#     assert get_ioc_category('filename.bat') == 'files'
#     assert get_ioc_category('otherfile.sh') == 'files'


# def test_get_ioc_category_valid_ip_addresses():
#     assert get_ioc_category('10.4.2.4') == 'ip_addresses'
#     assert get_ioc_category(
#         '2001:db8:3333:4444:5555:6666:7777:8888:') == 'ip_addresses'
#     assert get_ioc_category('0.0.0.0') == 'ip_addresses'
#     assert get_ioc_category('2001:db8::1:0:0:1') == 'ip_addresses'
#     assert get_ioc_category('10.3.45.10') != 'files'


# # def test_get_ioc_category_valid_domain():
# #     assert get_ioc_category('google.com') == 'domains'
# #     assert get_ioc_category('google.org') == 'domains'
# #     assert get_ioc_category('google.net') == 'domains'
# #     assert get_ioc_category('google.edu') == 'domains'
# #     assert get_ioc_category('google.top') == 'domains'
# #     assert get_ioc_category('google.xyz') == 'domains'


# # def test_get_ioc_category_valid_url():
# #     assert get_ioc_category('www.google.com') == 'urls'
# #     assert get_ioc_category('http://www.google.com') == 'urls'
# #     assert get_ioc_category('https://www.google.com') == 'urls'
# #     assert get_ioc_category('www.google.org') == 'urls'
# #     assert get_ioc_category('http://www.google.org') == 'urls'
# #     assert get_ioc_category('https://www.google.org') == 'urls'
# #     assert get_ioc_category('www.google.net') == 'urls'
# #     assert get_ioc_category('http://www.google.net') == 'urls'
# #     assert get_ioc_category('https://www.google.net') == 'urls'
# #     assert get_ioc_category('www.google.edu') == 'urls'
# #     assert get_ioc_category('http://www.google.edu') == 'urls'
# #     assert get_ioc_category('https://www.google.edu') == 'urls'
# #     assert get_ioc_category('http://www.google.top') == 'urls'
# #     assert get_ioc_category('https://www.google.top') == 'urls'
# #     assert get_ioc_category('www.google.xyz') == 'urls'
# #     assert get_ioc_category('http://www.google.xyz') == 'urls'
# #     assert get_ioc_category('https://www.google.xyz') == 'urls'


# def test_is_filename_invalid():
#     assert is_filename('10.5.23.44') == False
#     assert is_filename('blahbal.10') == False
#     assert is_filename('hello.x') == False
#     assert is_filename('2001:db8:3333:4444:5555:6666:7777:8888:') == False
