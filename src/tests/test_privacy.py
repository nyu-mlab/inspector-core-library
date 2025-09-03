import unittest
from libinspector.privacy import is_ad_tracked


class TestGetCountryFromIpAddr(unittest.TestCase):

    # If you check android-tds.json, you'll see a key with "www.google.com"
    def test_domain_with_ads(self):
        result = is_ad_tracked('www.google.com')
        self.assertEqual(result, True)

    # Momo Lab is here to protect your data :)
    def test_domain_with_no_ads(self):
        result = is_ad_tracked('momolab.com')
        self.assertEqual(result, False)


if __name__ == '__main__':
    unittest.main()