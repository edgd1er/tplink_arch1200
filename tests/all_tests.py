import os
import sys
import unittest

import test_duckdns
import test_archer1200
import test_noip
import test_updateDuckDns

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

loader = unittest.TestLoader()
suite = unittest.TestSuite()
suite.addTests(loader.loadTestsFromModule(test_duckdns))
suite.addTests(loader.loadTestsFromModule(test_archer1200))
suite.addTests(loader.loadTestsFromModule(test_noip))
suite.addTests(loader.loadTestsFromModule(test_updateDuckDns))

if __name__ == "__main__":
    runner = unittest.TextTestRunner(verbosity=3)
    runner.run(suite)
