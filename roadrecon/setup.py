from setuptools import setup
setup(name='roadrecon',
      version='1.7.3',
      description='Azure AD recon for red and blue',
      author='Dirk-jan Mollema',
      author_email='dirkjan@dirkjanm.io',
      url='https://github.com/dirkjanm/ROADtools/',
      license='MIT',
      classifiers=[
          'Intended Audience :: Information Technology',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
          'Programming Language :: Python :: 3.13',
      ],
      packages=[
        'roadtools.roadrecon',
        'roadtools.roadrecon.plugins',
        'roadtools.roadrecon.dist_gui',
        'roadtools.roadrecon.dist_gui.assets'
      ],
      package_data={
        'roadtools.roadrecon.plugins': ['*.yaml'],
        'roadtools.roadrecon.dist_gui': ['*'],
        'roadtools.roadrecon.dist_gui.assets': ['*'],
      },
      install_requires=[
          'roadlib>=0.21',
          'flask<3',
          'sqlalchemy>=1.4',
          'marshmallow<4',
          'flask-sqlalchemy>=2.5',
          'flask-marshmallow',
          'flask-cors',
          'marshmallow-sqlalchemy>=0.29',
          'aiohttp',
          'openpyxl'
      ],
      extras_require={
          'road2timeline': ['pyyaml', 'numpy', 'pandas']
      },
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['roadrecon-gui=roadtools.roadrecon.server:main',
                              'roadrecon=roadtools.roadrecon.main:main']
      }
      )
