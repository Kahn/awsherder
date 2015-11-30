from setuptools import setup

setup(name='awsherder',
      version='1.0',
      description='OpenShift App',
      author='Sam Wilson',
      author_email='swilsonau@gmail.com',
      url='http://www.cycloptivity.net',
      install_requires=
        [
        'Flask==0.10.1',
        'Flask-OpenID',
        'Flask-SQLAlchemy',
        'Flask-WTF',
        'Flask-SSLify',
        'SQLAlchemy',
        'python-openid',
        'Werkzeug',
        'wtforms'
        ],
     )
