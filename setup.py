from setuptools import setup, find_packages

# Function to read the requirements.txt file
def parse_requirements(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file if line.strip() and not line.startswith('#')]

setup(
    name='libinspector',
    version='0.1.0',
    author='NYU mLab',
    author_email='your_email@example.com',
    description='Library for core functionalities of IoT Inspector',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/nyu-mlab/inspector-core-library',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    package_data={
        'libinspector': ['wireshark_oui_database.txt'],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
    install_requires=parse_requirements('requirements.txt'),  # Include requirements from requirements.txt
)