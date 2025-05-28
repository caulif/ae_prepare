from setuptools import setup, Extension
from Cython.Build import cythonize
import numpy

extensions = [
    Extension(
        "vss_cy",
        ["vss_cy.pyx"],
        include_dirs=[numpy.get_include()],
        extra_compile_args=["-O3", "-march=native"],
    ),
    Extension(
        "vss_parallel",
        ["vss_parallel.pyx"],
        include_dirs=[numpy.get_include()],
        extra_compile_args=["-O3", "-march=native", "-fopenmp"],
        extra_link_args=["-fopenmp"],
    )
]

setup(
    name="vss_optimized",
    ext_modules=cythonize(extensions, compiler_directives={
        'language_level': "3",
        'boundscheck': False,
        'wraparound': False,
        'cdivision': True,
    }),
    zip_safe=False,
) 