import sys
import os

# Add python directory to path
sys.path.append(os.path.join(os.getcwd(), 'python'))

try:
    from cryptopdc.bindings import cryptopdc_bindings as core
    print("Bindings loaded successfully!")
    
    # Test MD5 CPU
    md5 = core.MD5()
    h = md5.hash("hello")
    print(f"MD5('hello') = {core.bytes_to_hex(h)}")
    
    # Test MD5 GPU (simulated call, won't launch kernel if no GPU or if we don't want to spin up)
    # Just checking function existence
    print(f"Has cuda_crack_md5: {hasattr(core, 'cuda_crack_md5')}")
    
except Exception as e:
    print(f"Failed to load bindings: {e}")
    sys.exit(1)
