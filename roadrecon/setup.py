from setuptools import setup
setup(name='roadrecon',
      version='1.0.1',
      description='Azure AD recon for red/blue',
      author='Dirk-jan Mollema',
      author_email='dirkjan@dirkjanm.io',
      url='https://github.com/dirkjanm/ROADtools/',
      license='MIT',
      classifiers=[
          'Intended Audience :: Information Technology',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
      ],
      packages=['roadtools.roadrecon', 'roadtools.roadrecon.plugins'],
      package_data={'roadtools.roadrecon.plugins': ['*.yaml']},
      install_requires=[
          'roadlib>=0.15',
          'flask',
          'sqlalchemy',
          'marshmallow',
          'flask-sqlalchemy>=2.5',
          'flask-marshmallow',
          'flask-cors',
          'marshmallow-sqlalchemy>=0.22',
          'aiohttp',
          'openpyxl'
      ],
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['roadrecon-gui=roadtools.roadrecon.server:main',
                              'roadrecon=roadtools.roadrecon.main:main']
      }
      )
