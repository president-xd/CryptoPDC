# CryptoPDC - Professional Distributed Cryptanalysis Framework
"""
CryptoPDC (Crypto Parallel Distributed Cracker) is a professional-grade
distributed cryptanalysis framework designed for high-performance
cryptographic analysis using both CPU and GPU resources.
"""

__version__ = "1.0.0"
__author__ = "CryptoPDC Team"

# Import submodules
from . import bindings
from . import distributed
from . import api

__all__ = ['bindings', 'distributed', 'api', '__version__']
