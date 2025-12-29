# Import the compiled bindings module
try:
    from . import cryptopdc_bindings
except ImportError as e:
    import warnings
    warnings.warn(f"Could not import cryptopdc_bindings: {e}. "
                  "Make sure the project is built first using CMake.")
    cryptopdc_bindings = None

__all__ = ['cryptopdc_bindings']
