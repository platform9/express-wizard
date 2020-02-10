"""General test of wizard.py"""

import os
import logging
import inspect
from unittest import TestCase
from subprocess import PIPE, Popen as popen

class TestWizardBaseLine(TestCase):
    """Wizard baseline tests"""
    def test_entrypoints(self):
        """Test wizard entry points"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        exit_status = os.system('wizard --test')
        assert exit_status == 0
        exit_status = os.system('wizard -t')
        assert exit_status == 0

    def test_usage_information(self):
        """Test wizard --help via direct subprocess call"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)
        output = popen(['wizard', '--help'], stdout=PIPE).communicate()[0]
        self.assertTrue('usage:' in str(output))
       
    def test_encryption(self):
        """Test wizard encryption class"""
        self.log = logging.getLogger(inspect.currentframe().f_code.co_name)
        print(self.log)
        output = "B"
        self.assertTrue(output == 'A')
        
