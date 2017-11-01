### pbkdf2helper

This Python module implements the basic PBKDF2 Helper-functions

Example:

    >>import pbkdf2helper

    >>encoded = pbkdf2helper.encode("secret", pbkdf2helper.generate_salt(), 1000)
    'sha256$1000$sooDhmF4$GloPulbaSfWsoIhU34mBzURTZTszCgfNoJ4myYcF1c4='

    >>pbkdf2helper.verify("secret", encoded)
    True

    >>pbkdf2helper.split(encoded)
    ('sha256', '1000', 'sooDhmF4', 'GloPulbaSfWsoIhU53mBzUXMZTszCgfNoJ4myYcF1c4=')

    >>pbkdf2helper.generate_salt(8)
    'f3a0bLXx'


copyright: (c) Copyright 2017 by Kungalex.
License: MIT