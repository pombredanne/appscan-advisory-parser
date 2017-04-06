from distutils.core import setup

setup(
      name='appscan-advisory-parser',
      version='0.1.1',
      author='Steve Coward',
      author_email='steve.coward@gmail.com',
      url='https://github.com/stevecoward/appscan-advisory-parser',
      license='LICENSE',
      description='Parses an IBM Appscan advisory XML file and extracts details from it.',
      packages=['appscan_advisory'],
)
