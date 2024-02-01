# Copyright (c) 2022 - 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

import pytest
import time
import logging
import subprocess
import threading
from contextlib import contextmanager
from typing import Dict

import psutil
import tomli

LOG = logging.getLogger(__name__)


def pytest_addoption(parser):
    parser.addoption("--device_type", action="store", default="vsock", help="Device type vsock/serial")
    parser.addoption("--servtd_hash", action="store", default="", help="SERVTD_INFO_HASH of MigTD image")

@pytest.fixture()
def device_type(request):
    return request.config.getoption("--device_type")

@pytest.fixture()
def servtd_hash(request):
    return request.config.getoption("--servtd_hash")

@contextmanager
def migtd_context():
    """
    Create a MigTD instance with default user id. Cleanup when out of scope.

    In most cases that are not necessary to run multiple pairs of TDs at the same time, use this method with `with` statement.
    """
    tool = MigtdTest()
    try:
        yield tool
    finally:
        tool.cleanup()


class MigtdTest:
    log_dir_name = f"log_{int(time.time())}"
    
    def __init__(self):
        # variable from the config file
        self.qemu: str = None
        self.migtd_hash_script: str = None
        self.mig_td_script: str = None
        self.user_td_script: str = None
        self.connect_script: str = None
        self.pre_mig_script: str = None
        self.user_td_bios_img: str = None
        self.kernel_img: str = None
        self.guest_img: str = None
        self.stress_test_cycles: str = None
        
        cfg = self._parse_toml_config()
        for k, v in cfg.items():
            setattr(self, k, v)
        
        # other variables to init
        self._threads: Dict[str, threading.Thread] = {}
        self._host_procs: Dict[str, subprocess.Popen] = {}
        self.ssh = None
        # clear dmesg
        self.clear_dmesg()
        # terminate all tds & socat before test execution
        self.cleanup()
        
    def _parse_toml_config(self) -> dict:
        with open("conf/pyproject.toml", "rb") as f:
            cfg = tomli.load(f)
        return cfg["migtd"]["config"]
    
    def _try_terminate_procs(self, popen: subprocess.Popen):
        if not popen:
            return
        try:
            root = psutil.Process(popen.pid)
            root_cmd = " ".join(root.cmdline())
            childs = root.children(recursive=True)
            LOG.debug(
                f"Terminate subprocess {list(map(lambda p: p.cmdline()[0], childs))} launched by '{root_cmd}'"
            )
        except psutil.NoSuchProcess:
            LOG.debug("Failed to terminate subprocess: NoSuchProcess")
            return
        for child in childs:
            child.terminate()
        root.terminate()
    
    def _wait_td_threads(self):
        for _, thread in self._threads.items():
            thread.join()
        self._threads = {}
    
    def _exec_shell_cmd(self, command: str, tag: str = None) -> tuple:
        LOG.debug(f"{command}\n")
        proc = subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if tag:
            self._host_procs[tag] = proc
        output, error = proc.communicate()
        stdout, stderr = output.decode().strip(), error.decode().strip()

        LOG.debug(f"{command}\n{stdout}\n")

        return (stdout, stderr)
    
    def start_test_payload(self, bios_img=None, type=None, device=None):
        """
        Start migration td
        """
        LOG.debug(f"Starting launch test td payload")
        arg=f"sudo bash {self.mig_td_script} -q {self.qemu} -m {bios_img} -t {type}"

        if device == "serial":
            arg=arg + " -s"
  
        thread_migtd =threading.Thread(
            target=self._exec_shell_cmd,
            args=(arg,
                  f"mig_td_{type}")
        )
        
        thread_migtd.start()

        self._threads[f"mig_td_{type}"] = thread_migtd
        time.sleep(1)
            
    # type has src dst
    def start_mig_td(self, bios_img=None, type=None, no_device=False, device=None):
        """
        Start migration td
        """
        arg=f"sudo bash {self.mig_td_script} -q {self.qemu} -m {bios_img} -t {type}"
        if no_device:
            arg=arg + " -n"
        if device == "serial":
            arg=arg + " -s"
            
        thread_migtd =threading.Thread(
            target=self._exec_shell_cmd,
            args=(arg,
                  f"mig_td_{type}")
        )
        
        LOG.debug(f"Starting {type} migration td")
        thread_migtd.start()
        self._threads[f"mig_td_{type}"] = thread_migtd
        time.sleep(1)
        
    # type has src dst
    def start_user_td(self, is_pre_binding=False, type=None, hash=None):
        command = f"sudo bash {self.user_td_script} -q {self.qemu} -i {self.guest_img} -k {self.kernel_img} -o {self.user_td_bios_img} -t {type}"
        if is_pre_binding:
            command += f" -g true -m {hash}"
        """
        Start user td
        """
        thread_usertd = threading.Thread(
            target=self._exec_shell_cmd,
            args=(command, f"user_td_{type}")
        )
        
        LOG.debug(f"Starting {type} user td")
        thread_usertd.start()
        self._threads[f"user_td_{type}"] = thread_usertd
        time.sleep(1)
        
    def connect(self):
        """
        Create a channel for MigTD_src and MigTD_dst
        """
        thread_connect =threading.Thread(
            target=self._exec_shell_cmd,
            args=(f"sudo bash {self.connect_script}",
                  "connect")
        )
        
        LOG.debug(f"Create a channel for MigTD_src and MigTD_dst")
        thread_connect.start()
        self._threads["connect"] = thread_connect
        time.sleep(5)
    
    def pre_migration(self, is_pre_binding=False):
        """
        Execute pre migration
        """
        LOG.debug(f"Start pre migration")
        command = f"sudo bash {self.pre_mig_script}"
        if is_pre_binding:
            command += " -p true"
        self._exec_shell_cmd(command)
    
    def check_migration_result(self, negative=False, wait_time=2):
        """
        Check pre-migration result
        """
        time.sleep(wait_time)
        runner = self._exec_shell_cmd("dmesg | tail -2")
        if runner[0] == "":
            time.sleep(3)
        runner = self._exec_shell_cmd("dmesg | tail -2")

        LOG.debug(runner[0])
        if negative:
            assert "pre-migration failed" in runner[0] or "Pre-migration is done" not in runner[0], "Negative: Not found 'Pre-migration failed'"
        else:
            assert "Pre-migration is done" in runner[0], "Function: Pre-migration failed"

    def terminate_mig_td(self, type=None):
        """
        Terminate the migration td qemu process with SIGTERM alone.
        """
        root_proc = self._host_procs.get(f"mig_td_{type}")
        self._try_terminate_procs(root_proc)
    
    def terminate_user_td(self, type=None):
        """
        Terminate the user td qemu process with SIGTERM alone.
        """
        root_proc = self._host_procs.get(f"user_td_{type}")
        self._try_terminate_procs(root_proc)
        
    def terminate_socat(self, type=None):
        """
        Terminate the migration td qemu process with SIGTERM alone.
        """
        self._exec_shell_cmd("ps aux | grep socat | grep -v grep | awk -F ' ' '{print $2}' | xargs sudo kill -9")
    
    def terminate_all_tds(self):
        """
        Terminate all td qemu processes with SIGTERM.
        """
        if len(self._host_procs) == 0:
            return
        self.terminate_user_td(type="src")
        self.terminate_user_td(type="dst")
        self.terminate_mig_td(type="src")
        self.terminate_mig_td(type="dst")
        self._host_procs = {}
        # Avoid terminate failed and cleanup existing migtd related td before running pytest
        self._exec_shell_cmd("ps aux | grep migtd | grep -v grep | awk -F ' ' '{print $2}' | xargs sudo kill -9")
    
    def clear_dmesg(self):
        self._exec_shell_cmd("sudo dmesg --clear")
    
    def cleanup(self):
        """
        Clear storage of threads and processes. And make sure all qemu procs have been terminated.
        """
        self.terminate_socat()
        self.terminate_all_tds()
        self._wait_td_threads()
        self._threads = {}
        self._host_procs = {}