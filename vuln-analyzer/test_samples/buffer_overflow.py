from ctypes import *

def vulnerable_buffer():
    # Buffer overflow vulnerability
    buffer = create_string_buffer(10)
    buffer.value = b"A" * 100  # Overflow!

    # Another buffer overflow
    name = create_string_buffer(5)
    name.value = b"This is a very long name that will overflow"

    return buffer.value 