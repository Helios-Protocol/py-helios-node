import msgpack_rlp as msgpack
import rlp_cython as rlp
from functools import partial

def encoding_function(obj):
    if isinstance(obj, rlp.Serializable):
        field_names = obj._meta.field_names
        class_name = type(obj).__name__

        attrs_to_encode = []
        for field_name in field_names:
            attrs_to_encode.append(getattr(obj, field_name))

        object_to_encode = {'n':class_name,
                            'a':attrs_to_encode}
        return object_to_encode

    return obj


def decoding_function(obj, sede_classes_dict = None):

    if sede_classes_dict is not None:
        class_name = obj['n']
        attrs = obj['a']
        new_class = sede_classes_dict[class_name]
        field_names = new_class._meta.field_names
        kwargs = dict(zip(field_names, attrs))
        return new_class(**kwargs)

    else:
        return obj


def get_family_class_list(classes_list):
    '''
    looks through the classes for any serializable sub classes
    '''
    for in_class in classes_list.copy():
        for sede in in_class._meta.sedes:
            if issubclass(sede, rlp.Serializable):
                children_lists = get_family_class_list([sede])
                classes_list.extend(children_lists)
    return classes_list



def make_classes_lookup_dict(classes_list, include_children_classes = False):
    if include_children_classes:
        complete_list = get_family_class_list(classes_list)
    else:
        complete_list = classes_list
    out_dict = {}
    for in_class in complete_list:
        class_name = in_class.__name__
        out_dict[class_name] = in_class

    return out_dict

def hm_encode(obj, sedes = None):
    encoded = msgpack.packb(obj, default=encoding_function, use_bin_type=True)
    return encoded

#TODO: need to stop rlp_templates from making lists immutable. need to add a switch.
def hm_decode(obj, sedes_classes = None, include_sedes_children_classes = False):
    if sedes_classes is not None:
        decoded = msgpack.unpackb(obj, object_hook=partial(decoding_function, sede_classes_dict=make_classes_lookup_dict(sedes_classes,include_sedes_children_classes)), raw=False)
    else:
        decoded = msgpack.unpackb(obj, raw=False)

    return decoded