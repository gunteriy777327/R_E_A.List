# COM type-library inventory verification — 2026-10-26

The analyst task is to read a Windows application's COM automation surface
(libraries, coclasses, interfaces, methods, DISPIDs, parameters, enums and
ProgIDs) from a `.tlb`/`.olb` file or a DLL/EXE with embedded `TYPELIB`
resources, on a Linux host, without loading, registering or calling the
server. CLI and MCP use the same application service and static parser.

## Decoder and its reference

The MSFT layout follows the reader in Wine's `dlls/oleaut32/typelib.c`
(`MSFT_Header`, segment directory, `MSFT_TypeInfoBase`, function and variable
records, `MSFT_ImpInfo`, and the type-description and custom-data encodings).
No Wine code is copied; field offsets and the optional-field rule (a field is
present when the fixed part of a record extends past it) were reimplemented.

## Independent writers

Two independent MSFT writers produced the samples. Expected values come from
their IDL sources, not from this decoder.

1. **Wine IDL compiler (widl 8.5, mingw-w64-tools 11.0.1).** The committed
   fixtures in `src/native/com/ComTypelib.fixture.ts` compile the IDL in
   `tests/fixtures/comTypelib/`, which declares its own `IUnknown`/`IDispatch`
   so no third-party IDL is embedded. They cover enum constants stored packed
   and in custom data, property accessor pairs, BSTR and integer default
   values, `SAFEARRAY`, a fixed `double[4][3]` array, local and imported
   (by GUID) references, coclass `default`/`source` roles, a dispinterface,
   a module, a record, an alias and Russian help strings in windows-1251 under
   LCID 0x419.
2. **Microsoft MIDL.** The type libraries shipped in the test suite of
   comtypes 1.4.8 (MIT; sdist SHA-256
   `bb2286cfb3b96f838307200a85b00b98e1bdebf1e58ec3c28b36b1ccfafac01f`) were
   decoded locally and compared with their IDL. They are not committed.

| Library              | SHA-256           | Checked against IDL                                                                                                                                                                                                                               |
| -------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TestComServer.tlb`  | `7ddc00b4…7fdd29` | Interface on IDispatch, propget/propput pair, `CURRENCY` default `32.78` as `"32.7800"`, `DATE` default `32`, mixed `[in]`/`[out]` parameters, coclass source interface, win32 vtable offsets (`28` for the first method after IDispatch's seven) |
| `TestDispServer.tlb` | `78a8b936…ab45aa` | Two dispinterfaces with dispatch properties and methods, DISPIDs 10–17 and 100–101                                                                                                                                                                |
| `mylib.tlb`          | `2afbfc25…13ef8`  | Two `dual` interfaces stored as one dispatch type info with `dual` flags, `SAFEARRAY(VARIANT*)`                                                                                                                                                   |
| `urlhist.tlb`        | `bb646b52…66685`  | `REFIID` parameters imported from stdole2 by type index (`stdole2.tlb#0`), records with `LPWSTR` and `_FILETIME` fields and their offsets, enums                                                                                                  |

All four decoded with `status: "decoded"` and no issues.

## Not verified

- No real commercial COM server was inspected in this environment; the target
  workflow (for example a CAD system's automation libraries) should be checked
  on its own files before relying on details such as code pages.
- Module entry points: widl writes no entry strings or ordinals, and none of
  the MIDL samples declares a module, so `entry` decoding follows Wine's reader
  without an independent sample.
- SLTG libraries are identified, not decoded.

## Cost

A widl library of 300 interfaces with 60 methods each (2.2 MB, 18,007
members) decoded with every member in 210–250 ms on this container, including
JSON serialization; the full result is 12.8 MB and the
`include_members: false` summary is 174 KB. Members are decoded only for
selected types, so `type_names` bounds both time and output.
