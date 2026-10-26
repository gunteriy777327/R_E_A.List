# COM type libraries

`inspect_com_typelib` / `inspect-com-typelib` answers which COM automation
surface one selected local file declares: the type libraries, coclasses,
interfaces, dispinterfaces, enums, records, aliases and modules, and, on
request, every method, property, parameter and constant. Many Windows
applications (CAD systems, office suites, engineering tools) publish their
automation API only as a type library, so this is often the most complete
static description of what a script or agent can call.

The input is either a standalone `.tlb`/`.olb` file or a PE32/PE32+ image
(DLL, EXE, OCX) whose `TYPELIB` resources embed one or more libraries. The file
is read without loading, registering or executing the server and without a
Windows host, COM runtime or SDK.

```bash
rea inspect-com-typelib /absolute/path/to/automation.tlb --summary --json
rea inspect-com-typelib /absolute/path/to/server.dll --type-name IApplication --json
```

The CLI resolves relative paths against the caller's working directory. MCP
and the advertised input schema require an absolute filesystem path:

```json
{
  "name": "inspect_com_typelib",
  "arguments": {
    "path": "/artifacts/automation.tlb",
    "include_members": false
  }
}
```

## Workflow for large libraries

Large automation libraries declare thousands of methods. Start with
`include_members: false` (`--summary`), which lists every type info with its
kind, GUID, flags, help string, implemented interfaces and member counts. Then
request `type_names` (`--type-name`, repeatable, case-insensitive) for the
interfaces that matter. Names that match no type are returned in
`unmatched_type_names`.

## Observations

The inline Evidence result contains the artifact path, SHA-256 and byte
length, and `container` (`typelib`, `pe32` or `pe32-plus`). Each entry in
`libraries[]` reports:

- `source`: the whole file, or the PE resource index, name and language;
  `location` and `sha256` identify the exact library bytes.
- `format` and `status`. MSFT libraries are decoded. SLTG libraries and
  resources without a recognized magic are `unsupported`. A library with
  unreadable records is `partial`, with `issues` naming file offsets.
- The LIBID (`guid`), name, version, LCID, `syskind`, library flags, help
  string, help file and help context.
- `imports[]`: libraries referenced through `importlib`, with their GUID,
  file name, version and LCID.
- `type_infos[]`: kind, name, GUID, version, flags (`dual`,
  `oleautomation`, `cancreate`, `hidden` and so on), help string, size,
  alignment and vtable size. `implemented[]` lists a coclass's interfaces with
  their `default`/`source` roles, or an interface's base interface.
  `alias_of` reports an alias target and `dll_name` a module's DLL.
- When members are reported: `functions[]` with member ID (DISPID),
  invoke kind (`func`, `propget`, `propput`, `propputref`), function kind,
  calling convention, vtable offset, flags, return type, parameters (name,
  type, `in`/`out`/`retval`/`optional` flags and default values), help string
  and module entry; and `variables[]` with record field offsets and enum or
  module constant values.

Types are reported as an IDL-like `text` (for example `IDocument**`,
`SAFEARRAY(BSTR)` or `double[4][3]`) with the `vt` of the outer type. A
user-defined type keeps its reference: `local` references name the target's
index in the same library, and `imported` references name the import and the
target's GUID or type index as the file records it.

ProgIDs are joined to coclasses by GUID from `registration_scripts[]`, which
reports the classes and ProgIDs declared by ATL registrar (`REGISTRY`)
resources in the same image. Replaceable parameters such as `%MODULE%` are kept
verbatim.

Narrow names and help strings use the ANSI code page implied by the library's
LCID; `string_code_page` reports the page and whether it came from the LCID,
the caller or the windows-1252 default for neutral locales. Pass `code_page`
(for example `1251`) when a neutral-LCID library carries localized help
strings.

## Limits and failures

The selected file is limited to 64 MiB by default (512 MiB maximum). PE images
examine at most 16384 resource directory entries by default (65536 maximum).
At most 65536 functions and variables are decoded across every library by
default (1048576 maximum); type infos whose members are not requested do not
count. Decoded text is limited to a fixed 32 MiB. Exhausted budgets and inputs
that are neither a type library nor a PE image fail without partial success;
the recovery names `type_names` and `include_members` for member budgets.

Malformed library headers, type infos, records and references are reported as
`partial` libraries and partial coverage with `issues`; earlier and later
entries survive.

This workflow does not observe registry state, class factories, run-time
`IDispatch` name lookups or `ITypeInfo` views that the COM runtime synthesizes
for dual interfaces. Each type info is reported as stored, and inherited
members appear only on their base interface. Custom data (IDL `custom`
attributes) and SLTG libraries are not decoded. Servers that register ProgIDs
in code, through `.reg` files or through installers declare ProgIDs this
inspection cannot see, and the absence of `TYPELIB` resources does not show
that a module exposes no COM classes.
