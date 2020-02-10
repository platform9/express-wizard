"""lib/lock.py"""
import os
import sys
import time

class Lock:
    """File locking for concurrent datamodel access"""

    TIMEOUT = 10

    def __init__(self):
        None

    def lassert(self, lock_name, m=None):
        sys.stdout.write("ERROR: {}".format(m))
        self.release_lock(lock_name)
        sys.exit(1)

    def get_lock(self, lock_name):
        cur_time = time.time()
        timeout_start = cur_time
        end_time = timeout_start + self.TIMEOUT
        while cur_time < end_time:
            try:
                os.mkdir(lock_name)
                break
            except Exception as ex:
                time.sleep(1)
            cur_time = time.time()

        # enforce timeout
        if cur_time >= end_time:
            self.lassert(lock_name,"failed to get lock: {} - TIMEOUT EXCEEDED".format(lock_name))
        if not os.path.isdir(lock_name):
            self.lassert(lock_name,"ERROR: failed to get lock: {}".format(lock_name))

    def release_lock(self, lock_name):
        if os.path.isdir(lock_name):
            try:
                os.rmdir(lock_name)
            except:
                self.lassert(lock_name,"ERROR: failed to release lock: {}".format(lock_name))
        if os.path.isfile(lock_name):
            self.lassert(lock_name,"ERROR: failed to release lock: {}".format(lock_name))

