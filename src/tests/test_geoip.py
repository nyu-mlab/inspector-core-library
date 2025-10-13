import unittest
import libinspector.privacy as privacy


class TestGetCountryFromIpAddr(unittest.TestCase):
    @unittest.skip("Skipping test to avoid external dependency")
    def test_private_ip(self):
        result = privacy.get_country_from_ip_addr('192.168.1.1')
        self.assertEqual(result, '(local network)')

    @unittest.skip("Skipping test to avoid external dependency")
    def test_public_ip_found(self):
        result = privacy.get_country_from_ip_addr('8.8.8.8')
        self.assertEqual(result, 'United States')

    @unittest.skip("Skipping test to avoid external dependency")
    def test_exception(self):
        result = privacy.get_country_from_ip_addr('8.8.4.4')
        self.assertEqual(result, 'United States')

    @unittest.skip("Skipping test to avoid external dependency")
    def test_public_ip_not_found(self):
        result = privacy.get_country_from_ip_addr('1.2.3.4')
        self.assertEqual(result, 'Australia')


if __name__ == '__main__':
    unittest.main()