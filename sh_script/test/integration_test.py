# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
integration_test.py

Readme:
--------------
A migtd test framework to help to test pre-migration and check dump logs.

- Please edit migtd.config variables in `pyproject.toml` before use.
- Please note running pytest requires sudo permission without being prompted to input a password.

Example:
Recommend to use python 3.10
--------------
$ python3 -m venv .venv
$ source .venv/bin/activate
$ (.venv) pip install pytest psutil pytest-html
$ (.venv) vim conf/pyproject.toml
$ (.venv) pytest

"""
import logging

from .conftest import migtd_context

LOG = logging.getLogger(__name__)

"""
Test Secure boot
"""
def test_function_001(device_type):
    migtd_src = "../../Bin/migtd_001.bin"
    migtd_dst = "../../Bin/migtd_001.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result()
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
RTMR1 of src and dst are not equal, but RTMR1 is not in policy file - SVN
"""
def test_function_002(device_type):
    migtd_src = "../../Bin/migtd_002.bin"
    migtd_dst = "../../Bin/migtd_001.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result()
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
RTMR1 of src and dst are not equal and RTMR1 is in policy file
"""
def test_function_negative_003(device_type):
    migtd_src = "../../Bin/migtd_003.bin"
    migtd_dst = "../../Bin/migtd_001.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Secure boot and svn(13) in range(13..18) of policy
"""
def test_function_004(device_type):
    migtd_src = "../../Bin/migtd_004.bin"
    migtd_dst = "../../Bin/migtd_004.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result()
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Secure boot and svn(17) in range(13..18) of policy
"""
def test_function_005(device_type):
    migtd_src = "../../Bin/migtd_005.bin"
    migtd_dst = "../../Bin/migtd_005.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result()
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Secure boot and svn(18) out of range(13..18)
"""
def test_function_negative_006(device_type):
    migtd_src = "../../Bin/migtd_006.bin"
    migtd_dst = "../../Bin/migtd_006.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Different policy file and check "Digest.MigTdPolicy"
"""       
def test_function_negative_007(device_type):
    migtd_src = "../../Bin/migtd_007.bin"
    migtd_dst = "../../Bin/migtd_no.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Invalid json
"""   
def test_function_negative_008(device_type):
    migtd_src = "../../Bin/migtd_008.bin"
    migtd_dst = "../../Bin/migtd_no.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Test without vsock device init
"""   
def test_function_negative_009(device_type):
    migtd_src = "../../Bin/migtd_009.bin"
    migtd_dst = "../../Bin/migtd_009.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_src, type="src", no_device=True, device=device_type)
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True, wait_time=10)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

def test_function_010(device_type):
    migtd_src = "../../Bin/migtd_010.bin"
    migtd_dst = "../../Bin/migtd_010.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result()
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

def test_function_011(device_type):
    migtd_src = "../../Bin/migtd_011.bin"
    migtd_dst = "../../Bin/migtd_011.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result()
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Secure boot and dst svn(2) greater than src svn(1) 
"""   
def test_function_012(device_type):
    migtd_src = "../../Bin/migtd_src_012.bin"
    migtd_dst = "../../Bin/migtd_dst_012.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result()
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Secure boot and dst svn(1) equal than src svn(1) 
""" 
def test_function_013(device_type):
    migtd_src = "../../Bin/migtd_src_013.bin"
    migtd_dst = "../../Bin/migtd_dst_013.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result()
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Secure boot and dst svn(1) smaller than src svn(2)
""" 
def test_function_negative_014(device_type):
    migtd_src = "../../Bin/migtd_src_014.bin"
    migtd_dst = "../../Bin/migtd_dst_014.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()
        
"""
Migration Policy Check:
Test operation "array-equal", sgxtcbcomponents is no equal with reference
""" 
def test_function_negative_015(device_type):
    migtd_src = "../../Bin/migtd_015.bin"
    migtd_dst = "../../Bin/migtd_015.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
Test operation "array-greater-or-equal", sgxtcbcomponents is smaller than reference
""" 
def test_function_negative_016(device_type):
    migtd_src = "../../Bin/migtd_016.bin"
    migtd_dst = "../../Bin/migtd_016.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
# Test polciy content is not correct, "fmspcx" shall be "fmspc"
""" 
def test_function_negative_017(device_type):
    migtd_src = "../../Bin/migtd_017.bin"
    migtd_dst = "../../Bin/migtd_017.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Migration Policy Check:
# Test polciy file does not contain actual platforms' fmspc
""" 
def test_function_negative_018(device_type):
    migtd_src = "../../Bin/migtd_018.bin"
    migtd_dst = "../../Bin/migtd_018.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_user_td(type="src")
        ctx.start_user_td(type="dst")
        if device_type == "vsock":
            ctx.connect()
        ctx.pre_migration()
        ctx.check_migration_result(negative=True)
        
        ctx.terminate_all_tds()
        ctx.terminate_socat()

"""
Test TD payload:
- MSR RW
- MMIO RW
- Quote Sevice Query
- Quote Attestation
""" 
def test_function_000(device_type):
    test_bin = "../../Bin/final-test.bin"
    
    with migtd_context() as ctx:
        ctx.start_test_payload(bios_img=test_bin, type="src", device=device_type)
        ctx.terminate_all_tds()

def test_pre_migration(target, device_type, servtd_hash, cycle_num):
    migtd_src = "../../target/release/migtd.bin"
    migtd_dst = "../../target/release/migtd.bin"

    if target == "debug":
        migtd_src = "../../target/debug/migtd.bin"
        migtd_dst = "../../target/debug/migtd.bin"
    
    with migtd_context() as ctx:
        ctx.start_mig_td(bios_img=migtd_dst, type="dst", device=device_type)
        ctx.start_mig_td(bios_img=migtd_src, type="src", device=device_type)
        if device_type == "vsock":
            ctx.connect()
        
        for i in range(cycle_num):
            LOG.debug(f"#### Cycle Test: {i + 1} ####")
            if device_type == "vsock":
                ctx.start_user_td(type="src")
                ctx.start_user_td(type="dst")
                ctx.pre_migration()
            else:
                ctx.start_user_td(type="src", is_pre_binding=True, hash=servtd_hash)
                ctx.start_user_td(type="dst", is_pre_binding=True, hash=servtd_hash)
                ctx.pre_migration(is_pre_binding=True)
            ctx.check_migration_result()
            ctx.terminate_user_td(type="src")
            ctx.terminate_user_td(type="dst")
        
        ctx.terminate_mig_td()
        ctx.terminate_socat()
