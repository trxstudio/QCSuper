#!/usr/bin/python3
#-*- encoding: Utf-8 -*-
from os.path import dirname, realpath
from setuptools import setup


SCRIPT_DIR = dirname(realpath(__file__))
README_PATH = SCRIPT_DIR + '/README.md'

with open(README_PATH) as fd:
    long_description = fd.read()

setup(name = 'qcsuper',
    version = '2.0.1',
    description = ' QCSuper is a tool communicating with Qualcomm-based phones and modems, allowing to capture raw 2G/3G/4G radio frames, among other things',
    author = 'P1 Security - Marin Moulinier',
    author_email = '',
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    entry_points = {
        'console_scripts': [
            'qcsuper = qcsuper.main:main'
        ]
    },
    url = 'https://github.com/P1sec/QCSuper',
    requires = ['pyserial(>=3.5)', 'pyusb(>=1.2.1)', 'crcmod(>=1.7)', 'pycrate(>=0.7.0)'],
    install_requires = [],
    include_package_data = True,
    package_data = {
        'qcsuper.inputs.adb_bridge': ['*'],
        'qcsuper.inputs.adb_wsl2_bridge': ['*'],
        'qcsuper.inputs.external': ['*'],
        'qcsuper.inputs.external.adb': ['*'],
        'qcsuper.inputs.external.adb.lib64': ['*'],
        'qcsuper.inputs.adb_bridge': ['*']
    },
    packages = [
        'qcsuper',
        'qcsuper.inputs',
        'qcsuper.inputs.adb_bridge',
        'qcsuper.inputs.adb_wsl2_bridge',
        'qcsuper.inputs.external',
        'qcsuper.inputs.external.adb',
        'qcsuper.inputs.external.adb.lib64',
        'qcsuper.protocol',
        'qcsuper.modules',
        'qcsuper.modules.efs_shell_commands'
    ],
    package_dir = {
        'qcsuper': 'src'
    }
)
