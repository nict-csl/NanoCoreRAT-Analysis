from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    README = f.read()

setup(
    name='NanoCoreAnalyzer',
    version='1.0.0',
    description='These are the scripts for NanoCore RAT analysis.',
    long_description=README,
    long_description_content_type='text/markdown',
    author='Takashi Matsumoto',
    author_email='tmatsumoto@nict.go.jp',
    package_dir={'': 'module'},
    packages=find_packages(where='module'),
    install_requires=[
        'pefile==2019.4.18',
        'pycryptodome==3.9.9',
    ],
    scripts=[
        'scripts/nanocore_extract_keys.py',
        'scripts/nanocore_extract_settings.py',
        'scripts/nanocore_decode_tcpflow.py',
        'scripts/nanocore_decode_file.py',
    ]
)
