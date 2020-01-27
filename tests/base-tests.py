"""General test of wizard.py"""

import os
import logging
import inspect

class TestWizardBaseLine()
    """Wizard baseline tests"""
    def test_entrypoints():
        exit_status = os.system('wizard --test')
        assert exit_status == 0
        exit_status = os.system('wizard -t')
        assert exit_status == 0

    def test_usage_information():
        
