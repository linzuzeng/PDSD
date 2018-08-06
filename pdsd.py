# Copyright (c) 2018 Zuzeng Lin
from typing import Union, List, Never, Optional
import struct, mmap, traceback, zlib, lzma, shutil


def data_decompress(data: bytes, compress=True, use_zlib=True):
    if not compress:
        return data
    elif use_zlib:
        return zlib.decompress(data)
    else:
        return lzma.decompress(data)


def data_compress(data: bytes, compress=True, use_zlib=True):
    if not compress:
        return data
    if use_zlib:
        return zlib.compress(data)
    else:
        return lzma.compress(data)


class File:
    def __init__(self, filename, mode="w", init_from_file=None):
        if mode == "w":
            if init_from_file is not None:
                shutil.copy(init_from_file, filename)
            try:
                self.file = open(filename, "r+b")
            except FileNotFoundError:
                with open(filename, "ab"):
                    pass
                    # print("empty file is created")
                self.file = open(filename, "r+b")
            self.mmapped = None
        else:
            self.file = open(filename, "rb")

            self.mmapped = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        self.mode = mode

        self.file.seek(0, 2)
        if self.file.tell() == 0:
            if "r" in self.mode:
                raise ValueError("Empty file")
            else:
                self.content = None

    def flush(self):
        self.file.flush()

    def __setattr__(self, name, userobj):
        if name == "content":
            # recursively dump the userobj
            root_node = BytesD(at_Disk=self, offset=0, length=None, compress=False)
            r = self._deep_copy(userobj)
            self.root_node = TreeD(
                at_BytesD=root_node,
                value=r,
                key=None,
                left=None,
                right=None,
            )

            # print(root_node.content)
            self.dirty = False
            self.flush()
            return r
        else:
            return super().__setattr__(name, userobj)

    def __getattr__(self, name):
        if name == "content":
            root_node = BytesD(at_Disk=self, offset=0, length=16 * 5, compress=False)
            self.root_node = TreeD(at_BytesD=root_node)
            # print("header", t)
            v = root_node.content
            # print("load", v)
            if v[0:2] == b"_N":
                # print(v)
                return self.byte2value(v[48:64])
            else:
                self.file.seek(0, 0)
                offset = int.from_bytes(self.file.read(8), "big")
                length = int.from_bytes(self.file.read(8), "big")
                self.file.seek(0, 2)
                print("legacy format at ", offset, length)
                return BytesD(at_Disk=self, offset=offset, length=length)
        else:
            return super().__getattribute__(name)

    def DictD(self, reference):
        return self._deep_copy(reference)

    def ListD(self, reference):
        return self._deep_copy(reference)

    def TupleD(self, reference):
        return self._deep_copy(reference)

    def SetD(self, reference):
        return self._deep_copy(reference)

    def ObjectD(self, reference):
        return self._deep_copy(reference)

    def BytesD(
        self, *vargs, from_content=None, offset=None, length=None, compress=True
    ):
        assert vargs == ()
        return BytesD(
            self,
            from_content=from_content,
            offset=offset,
            length=length,
            compress=compress,
        )

    def StringD(
        self, *vargs, from_content=None, offset=None, length=None, compress=True
    ):
        assert vargs == ()
        return StringD(
            self,
            from_content=from_content,
            offset=offset,
            length=length,
            compress=compress,
        )

    def to_file(self, reference):
        return self._deep_copy(reference)

    # context manager
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.file.close()
        return False

    def to_mem(self, from_):
        if isinstance(from_, DictD):
            to = dict()
            for each in from_:
                k = self.to_mem(each)
                to[k] = self.to_mem(from_[each])
        elif isinstance(from_, ListD):
            to = list()
            for i in range(len(from_)):
                to.append(self.to_mem(from_[i]))

        elif isinstance(from_, TupleD):
            from_ = list()
            for i in range(len(from_)):
                to.append(self.to_mem(from_[i]))
            to = tuple(from_)
        elif isinstance(from_, SetD):
            to = set()
            for each in from_:
                to.add(self.to_mem(each))
        elif (
            isinstance(from_, StringD)
            or isinstance(from_, BytesD)
            or isinstance(from_, ShortD)
            or isinstance(from_, ObjectD)
        ):
            to = from_.content
        else:
            raise ValueError("Unsupported type", type(from_), from_)
        return to

    def _deep_copy(self, from_):
        # print(traceback.print_stack())
        if isinstance(from_, ObjectD):
            # deep copy the object
            from_ = ObjectD(
                at_Disk=self, dict_on_disk=self._deep_copy(from_.dict_on_disk)
            )
        value = from_
        T = None
        # deep copy all other types
        if isinstance(from_, dict) or (
            isinstance(from_, DictD) and from_.at_BytesD.at_Disk != self
        ):
            keys = sorted(from_.keys())
            if len(keys) > 0:
                value = self._to_bst(from_=from_, keys=keys)
            else:
                T = DictD

        elif isinstance(from_, set) or (
            isinstance(from_, SetD) and from_.at_BytesD.at_Disk != self
        ):
            keys = sorted(list(from_))
            if len(keys) > 0:
                value = self._to_bst(from_=from_, keys=keys)
            else:
                T = SetD
        elif isinstance(from_, list) or (
            isinstance(from_, ListD) and from_.at_BytesD.at_Disk != self
        ):
            keys = list(range(len(from_)))
            if len(keys) > 0:
                value = self._to_bst(from_=from_, keys=keys)
            else:
                T = ListD
        elif isinstance(from_, tuple) or (
            isinstance(from_, TupleD) and from_.at_BytesD.at_Disk != self
        ):
            keys = list(range(len(from_)))
            if len(keys) > 0:
                value = self._to_bst(from_=from_, keys=keys)
            else:
                T = TupleD
        elif isinstance(from_, str) or (
            isinstance(from_, StringD) and from_.at_Disk != self
        ):
            if len(from_.encode("utf-8")) <= 13:
                value = ShortD(from_)
            else:
                if isinstance(from_, StringD) and from_.at_Disk != self:
                    value = StringD(from_content=from_.content, at_Disk=self)
                else:
                    value = StringD(from_content=from_, at_Disk=self)

        elif isinstance(from_, bytes) or (
            isinstance(from_, BytesD) and from_.at_Disk != self
        ):
            if len(from_) <= 13:
                value = ShortD(from_)
            else:
                if isinstance(from_, BytesD) and from_.at_Disk != self:
                    value = BytesD(from_content=from_.content, at_Disk=self)
                else:
                    value = BytesD(from_content=from_, at_Disk=self)

        elif (
            isinstance(from_, bool)
            or isinstance(from_, int)
            or isinstance(from_, float)
        ):
            value = ShortD(from_)
        elif (
            isinstance(from_, ListD)
            or isinstance(from_, DictD)
            or isinstance(from_, TupleD)
            or isinstance(from_, SetD)
        ):
            assert from_.at_BytesD.at_Disk == self, f"Invalid Disk {from_}"
        elif (
            isinstance(from_, BytesD)
            or isinstance(from_, StringD)
            or isinstance(from_, ObjectD)
        ):
            assert from_.at_Disk == self, f"Invalid Disk {from_}"
        elif from_.__class__.__name__ == "ndarray":
            return ObjectD(from_content=from_, at_Disk=self)
        elif from_ is None or isinstance(from_, ShortD) or from_ or from_ == KeyError:
            value = value
        else:
            # print("Value Error ",from_)
            return ObjectD(from_content=from_, at_Disk=self)
        if T is not None:
            ###bug me
            bytebackend = BytesD(at_Disk=self, compress=False)
            return T(
                at_BytesD=bytebackend,
                key=None,
                value=KeyError,
                left=None,
                right=None,
            )
        else:
            # print(value)
            return value

    # keys are array of integers or floats or strings or bytes
    def _to_bst(
        self, from_, keys: Union[List[Union[int, float, str, bytes]], List[Never]]
    ):
        if keys:
            mid = len(keys) // 2
            left = self._to_bst(from_, keys[:mid])
            right = self._to_bst(from_, keys[mid + 1 :])
            key = (
                keys[mid]
                if (
                    isinstance(from_, dict)
                    or isinstance(from_, tuple)
                    or isinstance(from_, set)
                    or isinstance(from_, DictD)
                    or isinstance(from_, TupleD)
                    or isinstance(from_, SetD)
                )
                else None
            )
            value = (
                from_[keys[mid]]
                if (
                    (
                        (isinstance(from_, dict) or isinstance(from_, DictD))
                        and keys[mid] in from_
                    )
                    or (
                        (
                            isinstance(from_, list)
                            or isinstance(from_, tuple)
                            or isinstance(from_, ListD)
                            or isinstance(from_, TupleD)
                        )
                        and keys[mid] >= 0
                        and keys[mid] < len(from_)
                    )
                )
                else None
            )

            value = self._deep_copy(value)
            # print("KeysToBST", keys, value)
            # from_dict.get(keys[mid])

            if isinstance(from_, dict) or isinstance(from_, DictD):
                T = DictD
            elif isinstance(from_, list) or isinstance(from_, ListD):
                T = ListD
            elif isinstance(from_, tuple) or isinstance(from_, TupleD):
                T = TupleD
            elif isinstance(from_, set) or isinstance(from_, SetD):
                T = SetD
            backend = BytesD(at_Disk=self, compress=False)
            node = T(
                at_BytesD=backend,
                key=key,
                value=value,
                left=left,
                right=right,
            )

            return node
        else:
            return None

    def value2byte(self, value):
        # dump anyways
        value = self._deep_copy(value)

        if isinstance(value, ShortD):
            t = value.storedbytes
            o = b""
            l = b""
        elif isinstance(value, ObjectD):
            assert value.at_Disk == self, "Invalid Disk"
            t = b"_M"
            o = value.dict_on_disk.at_BytesD.offset.to_bytes(8, "big")
            l = value.dict_on_disk.at_BytesD.length.to_bytes(6, "big")
        elif isinstance(value, DictD):
            assert value.at_BytesD.at_Disk == self, "Invalid Disk"
            t = b"_D"
            o = value.at_BytesD.offset.to_bytes(8, "big")
            l = value.at_BytesD.length.to_bytes(6, "big")
        elif isinstance(value, ListD):
            assert value.at_BytesD.at_Disk == self, "Invalid Disk"
            t = b"_L"

            o = value.at_BytesD.offset.to_bytes(8, "big")
            l = value.at_BytesD.length.to_bytes(6, "big")
        elif isinstance(value, TupleD):
            assert value.at_BytesD.at_Disk == self, "Invalid Disk"
            t = b"_T"
            o = value.at_BytesD.offset.to_bytes(8, "big")
            l = value.at_BytesD.length.to_bytes(6, "big")
        elif isinstance(value, SetD):
            assert value.at_BytesD.at_Disk == self, "Invalid Disk"
            t = b"_E"
            o = value.at_BytesD.offset.to_bytes(8, "big")
            l = value.at_BytesD.length.to_bytes(6, "big")
        elif isinstance(value, StringD):
            assert value.at_Disk == self, "Invalid Disk"
            t = b"_S"
            o = value.offset.to_bytes(8, "big")
            l = value.length.to_bytes(6, "big")
        elif isinstance(value, BytesD):
            assert value.at_Disk == self, "Invalid Disk"
            t = b"_B"
            o = value.offset.to_bytes(8, "big")
            l = value.length.to_bytes(6, "big")
        elif value is None:
            t = b"_N"
            o = int(0).to_bytes(8, "big")
            l = int(0).to_bytes(6, "big")
        elif KeyError == value:
            t = b"_h"
            o = int(0).to_bytes(8, "big")
            l = int(0).to_bytes(6, "big")
        else:
            raise ValueError("Unsupported type", type(value), value)
        ret = b"".join((t, o, l))
        assert len(ret) == 16, "Invalid length{}".format(len(ret))
        return ret

    def byte2value(self, value):
        assert len(value) == 16, "Invalid value"
        t = value[0:2]
        if t in [b"_i", b"_f", b"_o", b"_s", b"_b"]:
            return ShortD(from_storedbytes=value)

        o = int.from_bytes(value[2:10], "big")
        l = int.from_bytes(value[10:16], "big")

        if t == b"_S":
            return StringD(at_Disk=self, offset=o, length=l)
        elif t == b"_B":
            return BytesD(at_Disk=self, offset=o, length=l)
        elif t == b"_L":
            if l == 0 and o == 0:
                return ShortD(from_storedbytes=value)
            return ListD(
                at_BytesD=BytesD(at_Disk=self, offset=o, length=l, compress=False),
            )
        elif t == b"_D":
            if l == 0 and o == 0:
                return ShortD(from_storedbytes=value)
            return DictD(
                at_BytesD=BytesD(at_Disk=self, offset=o, length=l, compress=False),
            )
        elif t == b"_T":
            if l == 0 and o == 0:
                return ShortD(from_storedbytes=value)
            return TupleD(
                at_BytesD=BytesD(at_Disk=self, offset=o, length=l, compress=False),
            )
        elif t == b"_E":
            if l == 0 and o == 0:
                return ShortD(from_storedbytes=value)
            return SetD(
                at_BytesD=BytesD(at_Disk=self, offset=o, length=l, compress=False),
            )
        elif t == b"_M":
            return ObjectD(
                at_Disk=self,
                dict_on_disk=DictD(
                    at_BytesD=BytesD(at_Disk=self, offset=o, length=l, compress=False),
                ),
            )

        elif t == b"_N":
            return None
        elif t == b"_h":
            return KeyError
        else:
            raise ValueError("Invalid type", t)


class BytesD:
    def __init__(
        self,
        at_Disk: File,
        from_content: bytes = None,
        offset=None,
        length=None,
        compress=True,
    ):
        self.offset = offset
        self.length = length
        self.compress = compress
        self.at_Disk = at_Disk

        if from_content is not None:
            self.content = from_content

    def __setattr__(self, name: str, cont):
        if name in ["content"]:
            # print("BytesOnDisk setattr", name, cont)

            assert isinstance(cont, bytes), "content should be bytes"

            ret = data_compress(cont, self.compress)
            if self.offset is None:
                self.at_Disk.file.seek(0, 2)
                self.offset = self.at_Disk.file.tell()
                # print("append to disk",self.at_Disk.file.tell())
                self.at_Disk.file.write(ret)
                self.length = len(ret)
            else:
                if self.length is not None:
                    # in place write
                    assert len(ret) == self.length, "Invalid length {}!={}".format(
                        len(ret), self.length
                    )
                else:
                    self.length = len(ret)
                self.at_Disk.file.seek(self.offset, 0)
                self.at_Disk.file.write(ret)

            if True:
                # verify
                self.at_Disk.file.seek(self.offset, 0)
                new = self.at_Disk.file.read(self.length)
                assert new == ret, "new bytes read{},{}".format(new, ret)
                self.at_Disk.file.seek(0, 2)
            assert self.length is not None and self.offset is not None
            return self
        else:
            super().__setattr__(name, cont)

    def __getattr__(self, name: str):
        if name in ["content"]:
            assert self.length, "Invalid length {} {}".format(self.offset, self.length)
            if self.at_Disk.mmapped is None:
                self.at_Disk.file.seek(self.offset, 0)
                v = data_decompress(self.at_Disk.file.read(self.length), self.compress)
                self.at_Disk.file.seek(0, 2)
                return v
            else:
                return data_decompress(
                    self.at_Disk.mmapped[self.offset : self.offset + self.length],
                    self.compress,
                )

        else:
            return super().__getattribute__(name)

    def __str__(self):
        return self.__repr__()

    def __len__(self):
        return len(self.content)

    def __repr__(self):
        # print("print string d ", self.content)
        return f"{self.__class__.__name__}(`{self.at_Disk.file.name}`,{self.content!r})"

    def __eq__(self, other):
        return self.content == other

    def __ne__(self, other):
        return self.content != other

    def __lt__(self, other):
        return self.content < other

    def __le__(self, other):
        return self.content <= other

    def __gt__(self, other):
        return self.content > other

    def __ge__(self, other):
        return self.content >= other

    def __hash__(self) -> int:
        return hash(self.content)


class StringD(BytesD):
    def __init__(self, *vargs, **kwargs):
        super().__init__(*vargs, **kwargs)

    def __getattr__(self, name: str):
        if name in ["content"]:
            v = super().__getattr__(name).decode("utf-8")

            return v
        else:
            return super().__getattr__(name)

    def __setattr__(self, name: str, cont):
        if name in ["content"]:
            assert (
                isinstance(cont, str)
                or isinstance(cont, StringD)
                or isinstance(cont, ShortD)
            ), "content should be string"
            super().__setattr__(name, cont.encode("utf-8"))
            return

        else:
            return super().__setattr__(name, cont)

    def encode(self, encoding):
        return self.content.encode(encoding)

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        # print("print string d ", self.content)
        return f"{self.__class__.__name__}(`{self.at_Disk.file.name}`,{self.content!r})"

    def __eq__(self, other):
        return self.content == other

    def __ne__(self, other):
        return self.content != other

    def __lt__(self, other):
        return self.content < other

    def __le__(self, other):
        return self.content <= other

    def __gt__(self, other):
        return self.content > other

    def __ge__(self, other):
        return self.content >= other

    def __hash__(self) -> int:
        return hash(self.content)


class ShortD:
    def __init__(self, from_content: str = None, from_storedbytes: bytes = None):
        self.storedbytes = b"\x00" * 16
        self.parent = None
        if from_storedbytes:
            self.storedbytes = from_storedbytes
        else:
            self.content = from_content

    def __getattr__(self, name: str):
        if name in ["content"]:
            assert self.storedbytes
            t = self.storedbytes[0:2]
            if t == b"_i":
                return struct.unpack(">q", self.storedbytes[2:10])[0]
            elif t == b"_f":
                return struct.unpack("d", self.storedbytes[2:10])[0]
            elif t == b"_o":
                return bool(int.from_bytes(self.storedbytes[2:10], "big"))
            elif t == b"_b":
                return b"" + self.storedbytes[3 : 3 + ord(self.storedbytes[2:3])]
            elif t == b"_s":
                return self.storedbytes[3 : 3 + ord(self.storedbytes[2:3])].decode(
                    "utf-8"
                )
            else:
                raise ValueError("Invalid type", t)
        else:
            return super().__getattr__(name)

    def __setattr__(self, name: str, value):
        if name in ["content"]:
            if isinstance(value, bytes):
                if len(value) > 13:
                    raise ValueError(
                        f"ShortD does not store {value!r}, longer than 13."
                    )

                t = b"_b"
                o = len(value).to_bytes(1, "big") + value + b"\x00" * (13 - len(value))
                l = b""
            elif isinstance(value, str):
                value = value.encode("utf-8")
                if len(value) > 13:
                    raise ValueError(
                        f"ShortD does not store {value!r}, longer than 13."
                    )
                t = b"_s"
                o = len(value).to_bytes(1, "big") + value + b"\x00" * (13 - len(value))
                l = b""
            elif isinstance(value, bool):
                t = b"_o"
                o = int(value).to_bytes(8, "big")
                l = int(0).to_bytes(6, "big")

            elif isinstance(value, int):
                t = b"_i"
                o = struct.pack(">q", value)
                l = int(0).to_bytes(6, "big")

            elif isinstance(value, float):
                t = b"_f"
                o = struct.pack("d", value)
                # pack as float64
                l = int(0).to_bytes(6, "big")

            else:
                raise ValueError("Invalid type", type(value), value)
            self.storedbytes = b"".join((t, o, l))
        else:
            return super().__setattr__(name, value)

    def __str__(self):
        return str(self.content)

    def __repr__(self):
        return f"{self.content!r}"

    def __eq__(self, other):
        return self.content == other

    def __ne__(self, other):
        return self.content != other

    def __lt__(self, other):
        return self.content < other

    def __le__(self, other):
        return self.content <= other

    def __gt__(self, other):
        return self.content > other

    def __ge__(self, other):
        return self.content >= other

    def __hash__(self) -> int:
        return hash(self.content)

    def __bool__(self):
        return bool(self.content)

    def __len__(self):
        return len(self.content)

    def __iter__(self):
        return iter(self.content)

    def __getitem__(self, key):
        return self.content[key]

    def __setitem__(self, key, value):
        self.content[key] = value

    def __delitem__(self, key):
        del self.content[key]

    def __contains__(self, item):
        return item in self.content

    def __add__(self, other):
        return self.content + other

    def __radd__(self, other):
        return other + self.content

    def __mul__(self, other):
        return self.content * other

    def __rmul__(self, other):
        return other * self.content

    def __mod__(self, other):
        return self.content % other

    def __rmod__(self, other):
        return other % self.content

    def __truediv__(self, other):
        return self.content / other

    def __rtruediv__(self, other):
        return other / self.content

    def __floordiv__(self, other):
        return self.content // other

    def __rfloordiv__(self, other):
        return other // self.content

    def __pow__(self, other):
        return self.content**other

    def __rpow__(self, other):
        return other**self.content

    def __lshift__(self, other):
        return self.content << other

    def __rlshift__(self, other):
        return other << self.content

    def __rshift__(self, other):
        return self.content >> other

    def __rrshift__(self, other):
        return other >> self.content

    def __and__(self, other):
        return self.content & other

    def __rand__(self, other):
        return other & self.content

    def __xor__(self, other):
        return self.content ^ other

    def __rxor__(self, other):
        return other ^ self.content

    def __or__(self, other):
        return self.content | other

    def __ror__(self, other):
        return other | self.content

    def __neg__(self):
        return -self.content

    def __pos__(self):
        return +self.content

    def __abs__(self):
        return abs(self.content)

    def __invert__(self):
        return ~self.content

    def __round__(self, n=None):
        return round(self.content, n)


class TreeD:
    # write proper type hints
    def __init__(
        self,
        at_BytesD: BytesD,
        *vargs,
        key=None,
        value=None,
        right: Optional["TreeD"] = None,
        left: Optional["TreeD"] = None,
        **kwargs,
    ):
        assert vargs == () and kwargs == {}, "Invalid args {} {}".format(vargs, kwargs)
        self.at_BytesD = at_BytesD

        assert isinstance(
            self.at_BytesD, BytesD
        ), f"Invalid type {type(self.at_BytesD)}"
        if self.at_BytesD.length is None:
            # print("create or override", left, right, key, value)
            lbyte = self.at_BytesD.at_Disk.value2byte(left)
            rbyte = self.at_BytesD.at_Disk.value2byte(right)
            kbyte = self.at_BytesD.at_Disk.value2byte(key)
            vbyte = self.at_BytesD.at_Disk.value2byte(value)
            # print("new tree", lbyte, rbyte, kbyte, vbyte)
            from_content = b"".join(
                [
                    lbyte,
                    rbyte,
                    kbyte,
                    vbyte,
                ]
            )
            self.at_BytesD.content = from_content

    def __getattr__(self, name: str):
        if name in ["left", "right", "key", "value"]:
            read_bytes = self.at_BytesD.content
            assert self.at_BytesD.at_Disk, "Invalid Disk"
            assert len(read_bytes) == 64, "Invalid length"
            if name == "left":
                v = self.at_BytesD.at_Disk.byte2value(read_bytes[0:16])
                assert isinstance(v, TreeD) or (v is None), "Invalid type {}".format(v)
                return v
            elif name == "right":
                v = self.at_BytesD.at_Disk.byte2value(read_bytes[16:32])

                assert isinstance(v, TreeD) or (v is None), "Invalid type {}".format(v)
                return v
            elif name == "key":
                return self.at_BytesD.at_Disk.byte2value(read_bytes[32:48])
            elif name == "value":
                return self.at_BytesD.at_Disk.byte2value(read_bytes[48:64])
        else:
            return super().__getattribute__(name)

    def __setattr__(self, name: str, new_) -> None:
        if name in ["left", "right", "key", "value"]:
            if name == "left":
                v = self.at_BytesD.content
                self.at_BytesD.content = b"".join(
                    (self.at_BytesD.at_Disk.value2byte(new_), v[16:])
                )
            elif name == "right":
                v = self.at_BytesD.content
                self.at_BytesD.content = b"".join(
                    (v[:16], self.at_BytesD.at_Disk.value2byte(new_), v[32:])
                )
            elif name == "key":
                v = self.at_BytesD.content
                self.at_BytesD.content = b"".join(
                    (v[:32], self.at_BytesD.at_Disk.value2byte(new_), v[48:])
                )
            elif name == "value":
                v = self.at_BytesD.content

                self.at_BytesD.content = b"".join(
                    (v[:48], self.at_BytesD.at_Disk.value2byte(new_))
                )
        else:
            return super().__setattr__(name, new_)

    def _range_query(
        self, node, low, high, return_key=True, return_value=False, return_node=False
    ):
        # print("range query",node)
        if node is None or node.value == KeyError:
            return
        assert isinstance(node, TreeD), "Invalid type {}".format(node)

        key_copy = node.key

        if low is None or low < key_copy:
            yield from self._range_query(node.left, low, high, return_key, return_value)
        if (low is None or low <= key_copy) and (high is None or key_copy <= high):
            # print("yeild", node,return_key,return_value)
            if return_key and return_value:
                yield (node.key, node.value)
            elif return_key:
                yield node.key
            elif return_value:
                # print("really yeild", node,low,high)
                yield node.value
            elif return_node:
                yield node
            else:
                raise ValueError("Invalid return type")
        if high is None or high > key_copy:
            yield from self._range_query(
                node.right, low, high, return_key, return_value
            )

    def _insert_or_update(self, node, key, value):
        # deep copy the value
        value = self.at_BytesD.at_Disk._deep_copy(value)

        # update root if it is empty
        if node.value == KeyError:
            node.value = value
            node.key = key
            return
        if key < node.key:
            if node.left is None:
                newbytesbackend = BytesD(at_Disk=self.at_BytesD.at_Disk, compress=False)

                node.left = type(node)(at_BytesD=newbytesbackend, key=key, value=value)
            else:
                self._insert_or_update(node.left, key, value)
        elif key > node.key:
            if node.right is None:
                newbytesbackend = BytesD(at_Disk=self.at_BytesD.at_Disk, compress=False)

                node.right = type(node)(at_BytesD=newbytesbackend, key=key, value=value)
            else:
                self._insert_or_update(node.right, key, value)
        else:
            assert isinstance(node, TreeD), "Invalid type"

            # print(f"Update the value from { node.value} to {value}")
            node.value = value

    def __str__(self) -> str:
        return self.__class__.__name__

    def __repr__(self):
        if True:
            return f"{self.__class__.__name__}(`{self.at_BytesD.at_Disk.file.name}`,"
        else:
            # get class name of self
            repr = (
                self.__class__.__name__
                + f"(file=({self.at_Disk.file.fileno()!r},{self.at_Disk.file.name!r},{self.at_Disk.mmapped!r},[{self.offset},{self.length}])"
            )
            if isinstance(self, TreeD):
                if self.key is not None:
                    repr += f", key={self.key!r}"
                if self.value is not None:
                    repr += ", value"
                    if isinstance(self.value, str) or isinstance(self.value, bytes):
                        repr += f"={self.value!r}"

                if self.left is not None:
                    repr += ", left"
                if self.right is not None:
                    repr += ", right"
                repr += ")"
            else:
                if self.content is not None:
                    repr += f", content={self.content!r}"
                repr += ")"
            return repr

    def _inorder_travel_for_insert_or_append(
        self, root, pos, new_value, do_read_only=True, do_replace=False
    ):
        if not do_read_only:
            new_value = self.at_BytesD.at_Disk._deep_copy(new_value)
        else:
            assert new_value is None
        stack = []
        current = root
        if current.value == KeyError:
            if do_read_only:
                return 0, current
            else:
                current.value = new_value
                return 0, current

        current_pos = 0
        assert pos is None or pos >= 0
        last_current = None
        while current is not None or len(stack) > 0:
            # left as much as possible
            while current is not None:
                stack.append(current)
                current = current.left

            current = stack.pop()

            last_current = current if current is not None else last_current
            if current_pos == pos and pos is not None and not do_read_only:
                if do_replace:
                    current.value = new_value
                    return current_pos, current
                else:
                    # do insert
                    ## bug me
                    bytebackend = BytesD(at_Disk=self.at_BytesD.at_Disk, compress=False)
                    new_node = type(self)(
                        at_BytesD=bytebackend,
                        key=None,
                        value=new_value,
                        left=current.left,
                        right=None,
                    )
                    current.left = new_node
                    return current_pos, new_node

            current_pos += 1
            # turn right
            current = current.right

        # insert at the end
        if do_read_only:
            return current_pos, last_current
        else:
            assert self.at_BytesD.at_Disk
            ## bug me
            bytebackend = BytesD(at_Disk=self.at_BytesD.at_Disk, compress=False)
            new_node = type(self)(
                at_BytesD=bytebackend,
                key=None,
                value=new_value,
                left=None,
                right=None,
            )
            last_current.right = new_node
            return current_pos, new_node

    def _delete(self, node, key):
        if node is None:
            return node

        if key < node.key:
            node.left = self._delete(node.left, key)
        elif key > node.key:
            node.right = self._delete(node.right, key)
        else:
            # Node with only one child or no child
            if node.left is None:
                temp = node.right
                node = None
                return temp
            elif node.right is None:
                temp = node.left
                node = None
                return temp

            # Node with two children, get the inorder successor (smallest in the right subtree)
            current = node.right
            while current.left is not None:
                current = current.left
            temp = current
            node.key = temp.key
            node.value = temp.value
            node.right = self._delete(node.right, temp.key)

        return node


class DictD(TreeD):
    def __init__(self, *vargs, **kwargs):
        super().__init__(*vargs, **kwargs)

    def keys(self, low=None, high=None):
        # print("calling keys")
        return self._range_query(self, low, high)

    def items(self, low=None, high=None):
        return self._range_query(self, low, high, return_key=True, return_value=True)

    def values(self, low=None, high=None):
        return self._range_query(self, low, high, return_key=False, return_value=True)

    def __iter__(self):
        return self.keys()

    def __getitem__(self, key):
        # print("dict __get_item__")
        # run the generator until the key is found
        for v in self.values(key, key):
            return v
        raise KeyError

    def __delitem__(self, key):
        self._delete(self, key)

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"{ super().__repr__()}{dict(self)!r})"

    def __contains__(self, key):
        for k in self.keys():
            if k == key:
                return True
        return False

    def __setitem__(self, count, value):
        self._insert_or_update(self, count, value)


class ListD(TreeD):
    def __init__(self, *vargs, **kwargs):
        super().__init__(*vargs, **kwargs)

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"{ super().__repr__()}{list(self)!r})"

    def values(root, pos=0, end_pos=None):
        # check for empty tree

        if root.value == KeyError:
            return
        assert pos >= 0
        stack = []
        current = root
        current_pos = 0
        while current or stack:
            # go left as much as possible
            while current:
                stack.append(current)
                current = current.left

            current = stack.pop()

            if current_pos >= pos and (end_pos is None or current_pos < end_pos):
                yield current.value

            current_pos += 1
            # turn right
            current = current.right

    # override len()
    def __len__(self):
        return self._inorder_travel_for_insert_or_append(
            self, None, None, do_read_only=True, do_replace=False
        )[0]

    def __getitem__(self, pos):
        if pos < 0:
            pos = len(self) + pos
        if isinstance(pos, slice):
            start = pos.start
            stop = pos.stop
            assert pos.step == 1 or pos.step is None
            return self.values(start, stop)
        for i, v in enumerate(self.values()):
            if i == pos:
                return v
        raise IndexError

    def insert(self, pos, value):
        if pos < 0:
            pos = len(self) + pos
        self._inorder_travel_for_insert_or_append(
            self, pos, value, do_read_only=False, do_replace=False
        )

    def append(self, value):
        self._inorder_travel_for_insert_or_append(
            self, None, value, do_read_only=False, do_replace=False
        )

    def dequeue(self):
        ret = self.__getitem__(0)
        self.__delitem__(0)
        return ret

    def last(self):
        return self._inorder_travel_for_insert_or_append(
            self, None, None, do_read_only=True, do_replace=False
        )[1]

    def __setitem__(self, pos, value):
        if pos < 0:
            pos = len(self) + pos
        self._inorder_travel_for_insert_or_append(
            self, pos, value, do_read_only=False, do_replace=True
        )

    def __iter__(self):
        return self.values()

    def __contains__(self, key):
        for k in self.values():
            if k == key:
                return True
        return False

    def __delitem__(self, pos):
        if pos < 0:
            pos = len(self) + pos
        assert pos >= 0

        parent = None
        current = self
        stack = []
        current_pos = 0

      
        while current is not None or len(stack) > 0:
            while current is not None:
                stack.append((parent, current))
                parent, current = current, current.left

            parent, current = stack.pop()

            if current_pos == pos:
 
                if current.left is None and current.right is None:
                   
                    if parent:
                        if parent.left == current:
                            parent.left = None
                        else:
                            parent.right = None
                    else:
                        self.value = KeyError  # Assuming root is the node to delete
                elif current.left is not None and current.right is None:
                  
                    if parent:
                        if parent.left == current:
                            parent.left = current.left
                        else:
                            parent.right = current.left
                    else:
                        self.left = current.left  # Current is root
                elif current.left is None and current.right is not None:
           
                    if parent:
                        if parent.left == current:
                            parent.left = current.right
                        else:
                            parent.right = current.right
                    else:
                        self.right = current.right  # Current is root
                else:
                 
                    successor = current.right
                    successor_parent = current
                    while successor.left is not None:
                        successor_parent, successor = successor, successor.left

                    current.value = successor.value  # Swap values
             
                    if successor_parent.left == successor:
                        successor_parent.left = successor.right
                    else:
                        successor_parent.right = successor.right

                return  # Node deleted, exit function
            current_pos += 1
            parent, current = current, current.right

        raise IndexError("Position out of bounds")


class TupleD(TreeD):
    def __init__(self, *vargs, **kwargs):
        super().__init__(*vargs, **kwargs)

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"{ super().__repr__()}{tuple(self)!r})"

    def values(self, low=None, high=None):
        return self._range_query(self, low, high, return_key=False, return_value=True)

    def __getitem__(self, key):
    
        for i, v in enumerate(self.values(key, key)):
            if i == key:
                return v
        raise IndexError

    def __iter__(self):
        return self.values()


class SetD(TreeD):
    def __init__(self, *vargs, **kwargs):
        super().__init__(*vargs, **kwargs)

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"{ super().__repr__()}{set(self)!r})"

    def keys(self, low=None, high=None):
        return self._range_query(self, low, high, return_key=True, return_value=False)

    def __iter__(self):
        return self.keys()

    # for in operator
    def __contains__(self, key):
        for k in self.keys():
            if k == key:
                return True
        return False

    def add(self, key):
        self._insert_or_update(self, key, None)

    def __delitem__(self, key):
        self._delete(self, key)


class ObjectD:
    def __init__(
        self, at_Disk: "File", from_content=None, dict_on_disk: "DictD" = None
    ):
        self.dict_on_disk = dict_on_disk
        self.at_Disk = at_Disk
        if from_content is not None:
            self.content = from_content

    def __setattr__(self, name, arr):
        if name in ["content"]:
            # Metadata containing the shape and dtype of the array
            if arr.__class__.__name__ == "ndarray":
                metadata = {
                    "shape": list(arr.shape),
                    "dtype": str(arr.dtype),
                    "bytes": arr.tobytes(),
                    "magic": "numpy",
                }
            elif arr.__class__.__name__ == "torch.Tensor":
                metadata = {
                    "shape": list(arr.shape),
                    "dtype": str(arr.dtype),
                    "bytes": arr.numpy().tobytes(),
                    "magic": "torch",
                }
            else:
                raise ValueError("Invalid type", arr)
            self.dict_on_disk = self.at_Disk._deep_copy(metadata)
        else:
            super().__setattr__(name, arr)

    def __getattr__(self, name):
        if name in ["content"]:
 
            if self.dict_on_disk["magic"] == "numpy":
                import numpy as np

              
                return np.frombuffer(
                    self.dict_on_disk["bytes"].content,
                    dtype=np.dtype(self.dict_on_disk["dtype"].content),
                ).reshape(
                    self.dict_on_disk.at_BytesD.at_Disk.to_mem(
                        self.dict_on_disk["shape"]
                    )
                )
            elif self.dict_on_disk["magic"] == "torch":
                import torch

                return torch.tensor(
                    self.dict_on_disk["bytes"].content,
                    dtype=torch.dtype(self.dict_on_disk["dtype"].content),
                ).reshape(
                    self.dict_on_disk.at_BytesD.at_Disk.to_mem(
                        self.dict_on_disk["shape"]
                    )
                )
            else:
                raise ValueError("Invalid magic number")
        else:
            return super().__getattr__(name)

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f"{self.__class__.__name__}(`{self.at_Disk.file.name}`,{self.content!r})"


if __name__ == "__main__":
    # allow shared access
    with File("test2.pdsd") as testfile2:
        b = BytesD(testfile2, b"very long bytes can be written first to disk")
        testfile2.content = {1: 1}
        a = testfile2.content
        # b.append(a)
        a[2] = b
        print("test2.pdsd", testfile2.content)
    with File("test1.pdsd", init_from_file="test2.pdsd") as testfile:
        import numpy as np

        arr = np.array([[1, 2, 3] * 1000, [4, 5, 6] * 1000], dtype=np.int32)
        arr = testfile.to_file(arr)
        print(arr)
        testfile.content[3] = [arr, ("hello", "world"), {"a", "b"}]

    with File("test1.pdsd", mode="r") as testfile:
        final = testfile.content

        print("read all to memory", testfile.to_mem(final))
        # testfile.content = None
        # this will delete the file
