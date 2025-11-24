from setuptools import setup
from Cython.Build import cythonize

setup(
    name="main_bot",
    ext_modules=cythonize("main_bot.py", compiler_directives={"language_level": "3"}),
)
