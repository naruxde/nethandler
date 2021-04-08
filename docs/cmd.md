# Reserved commands

    b'\x06\x16': Reset timeout
    b'\x06A':    Auth request
    b'\x06C':    Configure Socket
    b'\x06F':    Call python function get pickled return value 
    b'\x06L':    Python function name as pickled <class 'list'>
    b'\x06\x04': Disconnect from server

    b'\x06E': Server reports exception with pickled python
    b'\x06O': Server returns pickled python function return value
    b'\x06R': Raw return value
    b'\x06X': Raw exception

    b'aa' - b'zz' | b'AA' - b'ZZ':  Raw user commands Byte IO
