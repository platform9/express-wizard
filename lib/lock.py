"""lib/lock.py"""
import os
import sys
import time

class Lock:
    """File locking for concurrent datamodel access"""

    TIMEOUT = 10

    def __init__(self, lock_name):
        self.lock_name = lock_name

    def lassert(self, m=None):
        sys.stdout.write("ERROR: {}".format(m))
        self.release_lock()
        sys.exit(1)

    def get_lock(self):
        cur_time = time.time()
        timeout_start = cur_time
        end_time = timeout_start + self.TIMEOUT
        while cur_time < end_time:
            try:
                os.mkdir(self.lock_name)
                break
            except Exception as ex:
                time.sleep(1)
            cur_time = time.time()

        # enforce timeout
        if cur_time >= end_time:
            self.lassert("ERROR: failed to get lock: {} - TIMEOUT EXCEEDED".format(self.lock_name))
        if not os.path.isdir(self.lock_name):
            self.lassert("ERROR: failed to get lock: {}".format(self.lock_name))

    def release_lock(self):
        if os.path.isdir(self.lock_name):
            try:
                os.rmdir(self.lock_name)
            except:
                self.lassert("ERROR: failed to release lock: {}".format(self.lock_name))
        if os.path.isfile(self.lock_name):
            self.lassert("ERROR: failed to release lock: {}".format(self.lock_name))

