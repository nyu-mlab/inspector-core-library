import unittest
from libinspector.oui_parser import get_vendor

class TestOUIParser(unittest.TestCase):

    def test_get_vendor(self):

        self.assertEqual(get_vendor('74:F8:DB:E0:00:00'), 'Bernard Krone Holding GmbH & Co. KG')
        self.assertEqual(get_vendor('8C:1F:64:00:30:00'), 'Brighten Controls LLP')
        self.assertEqual(get_vendor('8C1E80000000'), 'Cisco Systems, Inc')

if __name__ == '__main__':
    unittest.main()