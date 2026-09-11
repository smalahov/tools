""" Code/Data Tags plugin for gdb

Registers a set of commands to add and maintain named marks assigned
to addresses in the address space of the inferior.

E.g. command `tag 0x555555555190 tag_name` adds a tag with name
tag_name and links it to address 0x555555555190. The plugin also
creates a symbol record in internal gdb symbol table for the specified 
address with the specified name, so standard gdb commands like
`break tag_name` and `watch tag_name` work the regular way.

In addition assigned tags are displayed as comments in disassembler
listing.

Registered commands:
    load-tags tags_file_name
        Loads previously saved tags from a file or creates new tags file.
        Must be called before attempt to add new tags.

    tag [ADDR] NAME
        Adds new tag with NAME and assigns it to address ADDR.
        Assign procedure tries to find a existing symbol (probably with some offset)
        and link to that symbol (e.g. __sysycall + 48) instead of the absolute address.
        If ADDR is omitted, $rip is used.

    info tags
        Lists all currently active tags.

    delete tag ADDR
        Deletes tag at address ADDR
"""

import os
import re
import zlib
import tempfile
import json

import gdb
import gdb.disassembler


# ----------------------------------------------------------------------
# Tags storage
# ----------------------------------------------------------------------

class TagException(Exception):
    pass


class Tag:
    def __init__(self, address, address_expr, name, file_name=None,
                 sym_file=None, enabled=True):
        self._name = name
        self._address = address
        self._address_expr = address_expr
        self._file_name = file_name
        self._sym_file = sym_file
        self._enabled = enabled

    def __str__(self):
        return f"0x{self._address:016x}\t{self._name}\t{self._address_expr}" \
               f" of {self._file_name}" + \
               (" [DISABLED]" if not self._enabled else "")

    @property
    def name(self):
        return self._name

    @property
    def address(self):
        return self._address

    @property
    def address_expr(self):
        return self._address_expr

    @property
    def enabled(self):
        return self._enabled

    def to_dict(self):
        return {
            "name": self._name,
            "address": self._address,
            "address_expr": self._address_expr,
            "file_name": self._file_name}

    @classmethod
    def from_dict(cls, src):
        return cls(src["address"],
            src["address_expr"],
            src["name"],
            src["file_name"])

        
class Tags:
    def __init__(self):
        self._tags = dict()
        self._file_name = None

    def __iter__(self):
        return self._tags.values().__iter__()

    def _check_file_name(self):
        if self._file_name is None:
            raise Exception("Tags file name is not set. "
                "Use `tags load FILENAME` to load from existing tags"
                "file or create a new one")

    @property
    def file_name(self):
        return self._file_name

    def add_tag(self, address_expr, name, save=True, do_match=True):
        if save:
            self._check_file_name()

        if tags := [t for t in self._tags.values() if t.name == name]:
            raise TagException(f"Tag with provided name already exists: {tags[0]}")

        # TODO: Check: name should not exist in symbols table
        try:
            address = int(gdb.parse_and_eval(f"(void*)(0 + {address_expr})"))
        except gdb.error as e:
            raise TagException(f"tag: invalid address: {e}")

        # Try to convert the address into a symbol-related expression
        # TODO: This command may return several lines !!!
        if do_match:
            if match := re.search(
                    "^(.+) in section",
                    gdb.execute(f"info symbol {address_expr}", to_string=True)):
                address_expr = match[1]
            else:
                # Failed to link the address to any symbol
                # TODO: Try to link to the mapped file+offset
                address_expr = f"0x{address:x}"
                pass

        if address in self._tags:
            raise TagException(f"Tag for address 0x{address:x} already exists"
                               f" with name {self._tags[address].name}")

        # Note - temporary symbol file should be kept for proper gdb behavior
        # (e.g. to be reloaded when the inferior restarts)
        sym_file = SymbolHelper.add_symbol(address, name)

        tag = Tag(address, address_expr, name, sym_file=sym_file)
        self._tags[address] = tag

        if save:
            self.save_to_file(self._file_name)

        return tag

    def get(self, address):
        return self._tags.get(address, None)

    def delete_tag(self, address, save=True):
        if save:
            self._check_file_name()
    
        if address not in self._tags:
            return

        if self._tags[address]._enabled:
            SymbolHelper.remove_symbol(self._tags[address]._sym_file.name)

        del self._tags[address]

        if save:
            self.save_to_file(self._file_name)

    def clear(self, save=True):
        if save:
            self._check_file_name()

        try:
            while True:
                address = next(iter(self._tags))
                self.delete_tag(address, save=False)

        except StopIteration:
            pass

        if save:
            self.save_to_file(self._file_name)

    def save_to_file(self, file_name):
        with open(file_name, "w") as f:
            f.write(json.dumps([t.to_dict() for t in self], indent=4))

    def load_from_file(self, file_name=None):
        file_name = file_name or self._file_name

        tags = []
        if os.path.exists(file_name):
            with open(file_name, "r") as f:
                # Convert to Tag() to ensure file format correctness
                tags = [Tag.from_dict(d) for d in json.loads(f.read())]

        # Properly delete existing tags (to remove corresponding symbols)
        for address in [*self._tags]:
            self.delete_tag(address, save=False)

        loaded = 0
        try:
            for tag in tags:
                old_address = tag.address
                try:
                    tag = self.add_tag(tag.address_expr, 
                                       tag.name, 
                                       save=False, 
                                       do_match=False)
                    loaded = loaded + 1
                except TagException as e:
                    gdb.warning(f"tag skipped: {tag}, reason {e}")
                    # Add the tag to the list anyway so we keep it in the 
                    # file after save_to_file()
                    tag._enabled = False
                    self._tags[tag.address] = tag

                if tag.address != old_address:
                    gdb.warning(f"tag {tag.name} relocated "
                          f"0x{old_address:x} -> 0x{tag.address:x}")

            self._file_name = file_name

            # In case the addresses of the symbols were changed
            self.save_to_file(file_name)

            return loaded
        except Exception as e:
            self.clear(save=False)
            self._file_name = None
            raise


# ----------------------------------------------------------------------
# Tags GDB Commands
# ----------------------------------------------------------------------

class TagCommand(gdb.Command):
    def __init__(self, tags):
        super().__init__(
            "tag",
            gdb.COMMAND_USER,
            gdb.COMPLETE_NONE)
        self._tags = tags

    def invoke(self, argument, from_tty):
        argv = gdb.string_to_argv(argument)

        if len(argv) < 1:
            raise gdb.GdbError("Usage: tag [ADDRESS EXPR] NAME")

        name = argv[-1]
        if len(argv) > 1:
            address_expr = " ".join(argv[0:-1])
        else:
            address_expr = f"0x{int(gdb.parse_and_eval("$rip")):x}"

        tag = self._tags.add_tag(address_expr, name)

        gdb.write(f"Tag created: {tag}\n")


class LoadTagsCommand(gdb.Command):
    def __init__(self, tags):
        super().__init__(
            "load-tags",
            gdb.COMMAND_USER,
            gdb.COMPLETE_NONE)
        self._tags = tags

    def invoke(self, argument, from_tty):
        argv = gdb.string_to_argv(argument)

        file_name = argv[0] if len(argv) > 0 else None

        loaded_cnt = self._tags.load_from_file(file_name)
        gdb.write(f"{loaded_cnt} tags loaded from {self._tags.file_name}\n")


class InfoTagsCommand(gdb.Command):
    def __init__(self, tags):
        super().__init__(
            "info tags",
            gdb.COMMAND_USER,
            gdb.COMPLETE_NONE)
        self.__tags = tags

    def invoke(self, argument, from_tty):
        gdb.write(f"\033[1m{"Address": <18}   {"Name": <36}    Address expr\033[0m\n");
        for tag in sorted((t for t in self.__tags if t.enabled), key=lambda x: x.address):
            gdb.write(f"0x{tag.address: <16x}   {tag.name: <36}    {tag.address_expr}\n");


class DeleteTagCommand(gdb.Command):
    def __init__(self, tags):
        super().__init__(
            "delete tag",
            gdb.COMMAND_USER,
            gdb.COMPLETE_NONE)
        self._tags = tags

    def invoke(self, argument, from_tty):
        argv = gdb.string_to_argv(argument)

        if len(argv) < 1:
            raise gdb.GdbError("Usage: delete tag ADDRESS")

        address = parse_address(argv[0])
        if address is None or address not in {t.address for t in self._tags}:
            raise gdb.GdbError(f"Address {argv[0]} is incorrect or is not tagged\n")

        self._tags.delete_tag(address)


# ----------------------------------------------------------------------
# Tags custom disassembler
# ----------------------------------------------------------------------

class TagsDisassembler(gdb.disassembler.Disassembler):
    def __init__(self, tags):
        super().__init__("gdb-tags")
        self.__tags = tags

    def __call__(self, info):
        # Call default built-in disassembler.
        if result := gdb.disassembler.builtin_disassemble(info):
            tag = self.__tags.get(info.address)

            if tag is None or not tag.enabled:
                return result

            parts = result.parts
            new_part = info.text_part(gdb.disassembler.STYLE_COMMENT_START,
                                      f"\t# TAG: {tag.name}")
            parts.append(new_part)

            return gdb.disassembler.DisassemblerResult(
                result.length,
                parts=parts
            )

        else:
            return None


class SymbolHelper:
    """ Helper class to add and delete debug symbols in gdb

    Uses compressed precompiled object file (with only one
    symbol name SYMBOL____...___ of length 64+) to create
    temporary object file and use it for add-symbol-file command

    Commands used to create template file:
        clang++ -O0 -g -shared template.asm -o template -nostartfiles
        strip -K SYMBOL_____...__ template
        objcopy --only-keep-debug template template_data
    """

    TEMPLATE_DATA = (
        b"\x78\x9c\xab\x77\xf5\x71\x63\x62\x64\x64\x80\x01"
        b"\x66\x06\x3b\x06\x04\x8f\x81\xc1\x01\x4a\x9f\x60"
        b"\x42\x16\xb3\x60\x60\x07\x92\xdc\x0c\x5c\x60\xb5"
        b"\x2c\x0c\xb8\xc1\x1b\xa8\x61\x51\x30\xfd\x02\x10"
        b"\x0a\x24\xcc\x8a\xc4\xc7\xa0\x19\x10\xea\xd0\xf5"
        b"\xb1\x20\xab\x53\x40\xa3\xd1\x01\x92\x3e\x36\x10"
        b"\x97\x1f\x2a\xac\x8f\x4a\xc3\xc0\x07\x34\x7d\x4c"
        b"\x24\xea\xe3\x80\xd2\x2c\x50\x7c\x02\xea\x01\x74"
        b"\x5a\x85\x01\x95\x86\x85\x61\xd0\xd3\x92\x14\x16"
        b"\x12\xec\x83\x85\x0f\x48\x8f\x08\x03\x28\xfe\x18"
        b"\x18\xdc\xfd\x42\x19\x3c\x7e\x0a\xee\xf6\x3c\x14"
        b"\x7e\xa2\x5f\xfa\x8e\xf8\x06\xe5\x6d\x9c\xf3\x34"
        b"\x44\x5f\x32\xe0\x01\x10\x73\x58\x31\xc2\x9f\x21"
        b"\x38\xd2\xd7\xc9\xdf\x27\x9e\x12\xc0\xc0\xa0\x57"
        b"\x5c\x99\x5b\x92\x98\x04\xa4\x4b\x8a\x20\x74\x06"
        b"\x8c\x95\x97\x5f\x92\xaa\x97\x9e\x57\xaa\x97\x54"
        b"\x9a\x99\x93\xa2\x9b\x99\xc2\x00\xe6\x65\x24\x16"
        b"\x67\x30\xe8\xa5\x54\xe6\x01\x75\x42\xe8\x92\x22"
        b"\x06\xbd\x92\xd4\x8a\x12\x06\xbd\xd4\x8c\xf8\xb4"
        b"\xa2\xc4\xdc\x54\xb0\x78\x62\x6e\x66\x32\x3e\x8f"
        b"\x11\x09\xa4\x81\x98\x9d\x01\x12\xdf\x20\x80\x2b"
        b"\xbe\x60\x00\x3d\xcd\xeb\x31\x40\xe2\x1e\xa6\xff"
        b"\x03\x54\x1f\x2c\xfd\xcb\x40\xc5\x99\xa1\x34\x07"
        b"\x03\x2a\xb0\x40\xd3\x2f\xc0\x84\xaa\x5f\x02\xc9"
        b"\x5e\x46\x24\xfd\x30\x71\x07\x34\xfd\x1a\x68\xfa"
        b"\x8d\xd0\xec\x63\x44\xe3\x7b\x40\xf5\xb3\xc1\x04"
        b"\xd0\xf2\x23\xba\x7a\x74\xff\xfb\xa1\xd9\x0f\xcf"
        b"\x8f\xe8\xe9\x09\x0a\xd0\xfd\x1f\x01\x15\x83\x85"
        b"\x0f\x3c\xdd\x43\xf3\x01\x2c\xbd\xc3\xec\x85\xe9"
        b"\x87\x19\xcf\x88\x6c\x37\x12\x80\xc5\x83\x01\x94"
        b"\xcf\x09\x55\x87\x1e\x7e\x9c\x48\x76\x23\x03\x05"
        b"\xa8\xa1\xae\x68\xe2\xe8\xe1\x21\x88\x43\x7f\x2a"
        b"\x54\x7f\x22\x01\xfd\x00\xcd\x9e\x5f\x7b"
    )
    MAX_SYM_LENGTH = 64

    @staticmethod
    def add_symbol(address, name):
        if len(name) > SymbolHelper.MAX_SYM_LENGTH:
            raise RuntimeError(f"Symbol name is too long, {len(name)}")

        if not re.fullmatch("[a-zA-Z_][a-zA-Z_0-9]*", name):  
            raise RuntimeError(f"Incorrect symbol name {name}")

        sym_file = tempfile.NamedTemporaryFile(prefix=f"tagsym_{address:x}_", buffering=0)
        template = bytearray(zlib.decompress(SymbolHelper.TEMPLATE_DATA))

        # Replace the placeholder with real symbol name
        pos = template.find(b"SYMBOL___")
        for i in range(len(name)):
            template[pos + i] = ord(name[i])
        template[pos + len(name)] = 0

        sym_file.write(template)

        gdb.execute(f"add-symbol-file {sym_file.name} 0x{address:x}", to_string=True)
    
        return sym_file

    @staticmethod
    def remove_symbol(file_name):
        gdb.execute(f"remove-symbol-file {file_name}", to_string=True)


def parse_address(str):
    try:
        return int(str)
    except Exception:
        pass

    try:
        return int(str, 16)
    except:
        return None

if "_tags_storage" in locals():
    global _tags_storage
    _tags_storage.clear(False)
    
# Tags stotage
_tags_storage = Tags()

# GDB commmands instances creation
TagCommand(_tags_storage)
LoadTagsCommand(_tags_storage)
InfoTagsCommand(_tags_storage)
DeleteTagCommand(_tags_storage)

# Custom disassembler registration
gdb.disassembler.register_disassembler(
    TagsDisassembler(_tags_storage)
)

gdb.write("Tags plugin loaded.\n")
