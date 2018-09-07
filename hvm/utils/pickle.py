 
import pickle as pickle_lib

def hp_encode(obj, sedes = None):
    #here we can use the sedes to check the types of obj. will implement in future
    return pickle_lib.dumps(obj)

def hp_decode(encoded):
    return pickle_lib.loads(encoded)