from setuptools import find_packages, setup

setup(
    name='netbox-paloalto',
    version='0.1',
    description='A NetBox plugin to list firewall rules associated with devices/virtual machines in Netbox.',
    url='https://github.com/rodvand/netbox-paloalto',
    author='Martin Rødvand',
    license='Apache 2.0',
    install_requires=["pandevice"],
    packages=find_packages(),
    include_package_data=True,
)
