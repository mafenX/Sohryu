from setuptools import setup, find_packages

setup(
    name="sohryu-iot-scanner",
    version="1.0.0",
    description="Sohryu IoT Device Scanner -- local-network IoT discovery, fingerprinting and credential testing",
    packages=find_packages(),
    include_package_data=True,
    package_data={"iotscan": ["data/*.txt"]},
    python_requires=">=3.9",
    install_requires=["requests>=2.28", "colorama>=0.4"],
    extras_require={"mdns": ["zeroconf>=0.130"]},
    entry_points={"console_scripts": ["iotscan=iotscan.cli:main"]},
)
