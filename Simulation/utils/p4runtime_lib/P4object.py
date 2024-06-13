
import google.protobuf.text_format
from google.protobuf import descriptor
import logging
from p4.v1 import p4runtime_pb2
from . import bytes_utils
from collections import OrderedDict

context=None

class _PrintContext:
    def __init__(self):
        self.skip_one = False
        self.stack = []

    def find_table(self):
        for msg in reversed(self.stack):
            if msg.DESCRIPTOR.name == "TableEntry":
                try:
                    return context.get_name_from_id(msg.table_id)
                except KeyError:
                    return None
        return None

    def find_action(self):
        for msg in reversed(self.stack):
            if msg.DESCRIPTOR.name == "Action":
                try:
                    return context.get_name_from_id(msg.action_id)
                except KeyError:
                    return None
        return None

    def find_controller_packet_metadata(self):
        for msg in reversed(self.stack):
            if msg.DESCRIPTOR.name == "PacketIn":
                return "packet_in"
            if msg.DESCRIPTOR.name == "PacketOut":
                return "packet_out"
        return None


def _sub_object(field, value, pcontext):
    id_ = value
    try:
        return context.get_name_from_id(id_)
    except KeyError:
        logging.error("Unknown object id {}".format(id_))


def _sub_mf(field, value, pcontext):
    id_ = value
    table_name = pcontext.find_table()
    if table_name is None:
        logging.error("Cannot find any table in context")
        return
    return context.get_mf_name(table_name, id_)


def _sub_ap(field, value, pcontext):
    id_ = value
    action_name = pcontext.find_action()
    if action_name is None:
        logging.error("Cannot find any action in context")
        return
    return context.get_param_name(action_name, id_)


def _sub_pkt_md(field, value, pcontext):
    id_ = value
    ctrl_pkt_md_name = pcontext.find_controller_packet_metadata()
    return context.get_packet_metadata_name_from_id(ctrl_pkt_md_name, id_)


def _gen_pretty_print_proto_field(substitutions, pcontext):
    def myPrintField(self, field, value):
        self._PrintFieldName(field)
        self.out.write(' ')
        if field.type == descriptor.FieldDescriptor.TYPE_BYTES:
            # TODO(antonin): any kind of checks required?
            self.out.write('\"')
            self.out.write(''.join('\\\\x{:02x}'.format(b) for b in value))
            self.out.write('\"')
        else:
            self.PrintFieldValue(field, value)
        subs = None
        if field.containing_type is not None:
            subs = substitutions.get(field.containing_type.name, None)
        if subs and field.name in subs and value != 0:
            name = subs[field.name](field, value, pcontext)
            self.out.write(' ("{}")'.format(name))
        self.out.write(' ' if self.as_one_line else '\n')

    return myPrintField


def _repr_pretty_proto(msg, substitutions):
    """A custom version of google.protobuf.text_format.MessageToString which represents Protobuf
    messages with a more user-friendly string. In particular, P4Runtime ids are supplemented with
    the P4 name and binary strings are displayed in hexadecimal format."""
    pcontext = _PrintContext()

    def message_formatter(message, indent, as_one_line):
        # For each messages we do 2 passes: the first one updates the _PrintContext instance and
        # calls MessageToString again. The second pass returns None immediately (default handling by
        # text_format).
        if pcontext.skip_one:
            pcontext.skip_one = False
            return
        pcontext.stack.append(message)
        pcontext.skip_one = True
        s = google.protobuf.text_format.MessageToString(
            message, indent=indent, as_one_line=as_one_line, message_formatter=message_formatter)
        s = s[indent:-1]
        pcontext.stack.pop()
        return s

    # We modify the "internals" of the text_format module which is not great as it may break in the
    # future, but this enables us to keep the code fairly small.
    saved_printer = google.protobuf.text_format._Printer.PrintField
    google.protobuf.text_format._Printer.PrintField = _gen_pretty_print_proto_field(
        substitutions, pcontext)

    s = google.protobuf.text_format.MessageToString(msg, message_formatter=message_formatter)

    google.protobuf.text_format._Printer.PrintField = saved_printer

    return s


def _repr_pretty_p4info(msg):
    substitutions = {
        "Table": {"const_default_action_id": _sub_object,
                  "implementation_id": _sub_object,
                  "direct_resource_ids": _sub_object},
        "ActionRef": {"id": _sub_object},
        "ActionProfile": {"table_ids": _sub_object},
        "DirectCounter": {"direct_table_id": _sub_object},
        "DirectMeter": {"direct_table_id": _sub_object},
    }
    return _repr_pretty_proto(msg, substitutions)


def _repr_pretty_p4runtime(msg):
    substitutions = {
        "TableEntry": {"table_id": _sub_object},
        "FieldMatch": {"field_id": _sub_mf},
        "Action": {"action_id": _sub_object},
        "Param": {"param_id": _sub_ap},
        "ActionProfileMember": {"action_profile_id": _sub_object},
        "ActionProfileGroup": {"action_profile_id": _sub_object},
        "MeterEntry": {"meter_id": _sub_object},
        "CounterEntry": {"counter_id": _sub_object},
        "ValueSetEntry": {"value_set_id": _sub_object},
        "RegisterEntry": {"register_id": _sub_object},
        "DigestEntry": {"digest_id": _sub_object},
        "DigestListAck": {"digest_id": _sub_object},
        "DigestList": {"digest_id": _sub_object},
        "PacketMetadata": {"metadata_id": _sub_pkt_md}
    }
    return _repr_pretty_proto(msg, substitutions)


class P4Object:
    def __init__(self, obj_type, obj):
        self.name = obj.preamble.name
        self.id = obj.preamble.id
        self._obj_type = obj_type
        self._obj = obj
        self.__doc__ = """
A wrapper around the P4Info Protobuf message for {} '{}'.
You can access any field from the message with <self>.<field name>.
You can access the name directly with <self>.name.
You can access the id directly with <self>.id.
If you need the underlying Protobuf message, you can access it with msg().
""".format(obj_type.pretty_name, self.name)

    def __dir__(self):
        d = ["info", "msg", "name", "id"]
        if self._obj_type == P4Type.table:
            d.append("actions")
        return d

    def _repr_pretty_(self, p, cycle):
        p.text(_repr_pretty_p4info(self._obj))

    def __str__(self):
        return _repr_pretty_p4info(self._obj)

    def __getattr__(self, name):
        return getattr(self._obj, name)

    def __settattr__(self, name, value):
        return UserError("Operation not supported")

    def msg(self):
        """Get Protobuf message object"""
        return self._obj

    def info(self):
        print(_repr_pretty_p4info(self._obj))

    def actions(self):
        """Print list of actions, only for tables and action profiles."""
        if self._obj_type == P4Type.table:
            for action in self._obj.action_refs:
                print(context.get_name_from_id(action.id))
        elif self._obj_type == P4Type.action_profile:
            t_id = self._obj.table_ids[0]
            t_name = context.get_name_from_id(t_id)
            t = context.get_table(t_name)
            for action in t.action_refs:
                print(context.get_name_from_id(action.id))
        else:
            raise UserError("'actions' is only available for tables and action profiles")

class P4Objects:
    def __init__(self, cn, obj_type):
        global context
        context=cn
        self._obj_type = obj_type
        self._names = sorted([name for name, _ in context.get_objs(obj_type)])
        self._iter = None
        self.__doc__ = """
All the {pnames} in the P4 program.
To access a specific {pname}, use {p4info}['<name>'].
You can use this class to iterate over all {pname} instances:
\tfor x in {p4info}:
\t\tprint(x.id)
""".format(pname=obj_type.pretty_name, pnames=obj_type.pretty_names, p4info=obj_type.p4info_name)

    def __call__(self):
        for name in self._names:
            print(name)

    def _ipython_key_completions_(self):
        return self._names

    def __getitem__(self, name):
        obj = context.get_obj(self._obj_type, name)
        if obj is None:
            raise UserError("{} '{}' does not exist".format(
                self._obj_type.pretty_name, name))
        return P4Object(self._obj_type, obj)

    def __setitem__(self, name, value):
        raise UserError("Operation not allowed")

    def _repr_pretty_(self, p, cycle):
        p.text(self.__doc__)

    def __iter__(self):
        self._iter = iter(self._names)
        return self

    def __next__(self):
        name = next(self._iter)
        return self[name]

class PacketMetadata:
    def __init__(self, metadata_info_list):
        self._md_info = OrderedDict()
        self._md = OrderedDict()
        # Initialize every metadata to zero value
        for md in metadata_info_list:
            self._md_info[md.name] = md
            self._md[md.name] = self._parse_md('0', md)
        self._set_docstring()

    def _set_docstring(self):
        self.__doc__ = "Available metadata:\n\n"
        for name, info in self._md_info.items():
            self.__doc__ += str(info)
        self.__doc__ += """
Set a metadata value with <self>.['<metadata_name>'] = '...'

You may also use <self>.set(<md_name>='<value>')
"""

    def __dir__(self):
        return ["clear"]

    def _get_md_info(self, name):
        if name in self._md_info:
            return self._md_info[name]
        raise UserError("'{}' is not a valid metadata name".format(name))

    def __getitem__(self, name):
        _ = self._get_md_info(name)
        print(self._md.get(name, "Unset"))

    def _parse_md(self, value, md_info):
        if type(value) is not str:
            raise UserError("Metadata value must be a string")
        md = p4runtime_pb2.PacketMetadata()
        md.metadata_id = md_info.id
        md.value = bytes_utils.parse_value(value.strip(), md_info.bitwidth)
        return md

    def __setitem__(self, name, value):
        md_info = self._get_md_info(name)
        self._md[name] = self._parse_md(value, md_info)

    def _ipython_key_completions_(self):
        return self._md_info.keys()

    def set(self, **kwargs):
        for name, value in kwargs.items():
            self[name] = value

    def clear(self):
        self._md.clear()

    def values(self):
        return self._md.values()
