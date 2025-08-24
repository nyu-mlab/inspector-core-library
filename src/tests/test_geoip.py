import unittest
import libinspector.trackers as trackers


class TestGetCountryFromIpAddr(unittest.TestCase):

    def test_private_ip(self):
        result = trackers.get_country_from_ip_addr('192.168.1.1')
        self.assertEqual(result, '(local network)')

    def test_public_ip_found(self):
        result = trackers.get_country_from_ip_addr('8.8.8.8')
        self.assertEqual(result, 'United States')

    def test_exception(self):
        result = trackers.get_country_from_ip_addr('8.8.4.4')
        self.assertEqual(result, 'United States')

    def test_public_ip_not_found(self):
        result = trackers.get_country_from_ip_addr('1.2.3.4')
        self.assertEqual(result, 'Australia')


if __name__ == '__main__':
    unittest.main()