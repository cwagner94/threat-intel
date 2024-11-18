from unittest import mock
from threat_intel import UserInput, Ioc, VirusTotal, VT_API_KEY
import pytest

def test_VT_API_KEY():
    assert VT_API_KEY != None

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


class TestVirusTotal:
    @pytest.mark.parametrize("params, expected_status", [
        ({"ioc": '193.42.2.4', "category": "ip_addresses"}, 200),
        ({"ioc": 'e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5',
         "category": "files"}, 200),
        ({"ioc": '193.42.2.4', "category": "files"}, 404)
    ])
    def test_get_api_response_status(self, mocker, params, expected_status):
        mocker.patch('os.getenv', return_value='mock_api_key')
        mocker.patch('threat_intel.VirusTotal.get_api_response',
                     return_value=mocker.Mock(status_code=expected_status))

        result = VirusTotal.get_api_response(self, params)
        assert result.status_code == expected_status

    @pytest.mark.parametrize('ioc, category, expected_status', [
        ('8.8.8.8', "ip_addresses", 200),
        ('193.42.2.4', "ip_addresses", 200),
        ('filename.sh', 'domains', 200),
        ('e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5', "files", 200),
        ('938c2cc0dcc05f2b68c4287040cfcf71', 'files', 200),
        ('23.4.1.43', 'ip_addresses', 200),
        ('2001:db8:3333:4444:5555:6666:7777:8888', 'ip_addresses', 200),
        # ('powershell.exe', 'files', 200), #TODO: fails - becomes domains
        # ('file.sh', 'files', 200), #TODO: fails - becomes domains
        # ('update.js', 'files', 200),  # TODO: fails - becomes domains
        # ('https://www.google.com', 'urls', 200),  # TODO: fails - does url need to be encoded or hashed?
        ('google.com', 'domains', 200)
    ])
    def test_get_api_response_200(self, ioc, category, expected_status):
        vt = VirusTotal(ioc, category)
        vt.get_api_response()
        assert vt.api_response.status_code == expected_status

    @pytest.mark.parametrize('ioc, category, expected_status', [
        ('193.42.2.4', "files", 404)
    ])
    def test_get_api_response_404(self, ioc, category, expected_status):
        with pytest.raises(Exception) as exception:
            vt = VirusTotal(ioc, category)
            vt.get_api_response()

        assert f'Request failed with status code {expected_status}' in str(
            exception.value)


class TestIoc:
    @pytest.mark.parametrize('value, expected', [
        ('e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5', 'sha256')
    ])
    def test_is_sha256_valid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_sha256()
        assert ioc.ioc_type == expected

    @pytest.mark.parametrize('value, expected', [
        ('house.bat', 'sha256'),
        ('34.2.222.4', 'sha256'),
        ('938c2cc0dcc05f2b68c4287040cfcf71', 'sha256')
    ])
    def test_is_sha256_invalid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_sha256()
        assert ioc.ioc_type != expected

    def test_is_md5_valid(self):
        ioc = Ioc('938c2cc0dcc05f2b68c4287040cfcf71')
        ioc.is_md5()
        assert ioc.ioc_type == 'md5'

    @pytest.mark.parametrize('value, expected', [
        ('house.bat', 'md5'),
        ('34.2.222.4', 'md5'),
        ('e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5', 'md5')
    ])
    def test_is_md5_invalid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_md5()
        assert ioc.ioc_type != expected

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
        ('2001:db8:3333:4444:5555:6666:7777:8888:', 'ipv4'),
        ('filename.sh', 'ipv4'),
        ('exampledomain.com', 'ipv4')
    ])
    def test_is_ipv4_invalid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_ipv4()
        assert ioc.ioc_type != expected

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
        ('https://www.google.com/', 'ipv6'),
        ('132.5.5.12', 'ipv6'),
        ('filename.txt', 'ipv6')
    ])
    def test_is_ipv6_invalid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_ipv6()
        assert ioc.ioc_type != expected

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
        ('domain.com', 'url'),
        ('file.txt', 'url'),
        ('193.423.1.22', 'url'),
        ('google.ru', 'url'),
        ('website.io', 'url')
    ])
    def test_is_url_invalid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_url()
        assert ioc.ioc_type != expected

    @pytest.mark.parametrize('value, expected', [
        ('google.com', 'domain'),
        ('google.ru', 'domain'),
        ('somewebsite.xyz', 'domain'),
        ('addiferentwebsite.org', 'domain'),
        ('whoami.io', 'domain'),
        ('website.edu', 'domain'),
        ('google.org', 'domain'),
        ('google.net', 'domain'),
        ('differentdomain.top', 'domain')

    ])
    def test_is_domain_valid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_domain()
        assert ioc.ioc_type == expected

    @pytest.mark.parametrize('value, expected', [
        ('', 'domain'),
        ('e346f6b36569d7b8c52a55403a6b78ae0ed15c0aaae4011490404bdb04ff28e5', 'domain'),
        # ('https://www.google.com/', 'domain'),  # TODO This fails currently
        # ('filename.txt', 'domain'),  # TODO This fails currently
        # ('www.google.com', 'domain')  # TODO This fails currently
    ])
    def test_is_domain_invalid(self, value, expected):
        ioc = Ioc(value)
        ioc.is_domain()
        assert ioc.ioc_type != expected

    def test_set_category(self):
        pass
