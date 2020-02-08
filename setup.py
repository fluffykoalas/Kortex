from setuptools import setup

setup(
    name='kortex',
    version='0.1',
    author='Fluffy Koalas security team',
    author_email='legorooj@protonmail.com',
    description='kortex provides the cryptographic backend to projects by fluffykoalas',
    url='https://github.com/fluffykoalas/kortex',
    packages=['kortex'],
    license='MIT',
    classifiers=[
        "Programming Language :: Python :: 3.7",
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 3 - Alpha'
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools'
    ],
    python_requires='>=3.7, <3.8',
    install_requires=['cryptography', 'pycryptodomex']
)
