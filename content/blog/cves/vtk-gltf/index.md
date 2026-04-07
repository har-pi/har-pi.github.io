---
title: "Shaking the Mesh: Four Memory Corruption Bugs in VTK's GLTF Loader"
date: 2025-10-30
description: "How fuzzing F3D's 3D file parser with a dictionary-based libFuzzer harness found four memory corruption vulnerabilities in VTK's GLTF document loader — two use-after-frees, a heap buffer overflow, and a buffer overread."
tags: ["cve", "research", "fuzzing", "memory-corruption", "vtk", "gltf"]
categories: ["vulnerability-research"]
draft: false
---

> *"The future is already here — it's just not evenly distributed."* — William Gibson

## How I Got Here

In late May 2025 I kicked off a seven-day engagement for [Radically Open Security](https://www.radicallyopensecurity.com/) targeting [F3D](https://f3d.app/) — a fast, minimalist 3D viewer that supports dozens of file formats — and its library counterpart, `libf3d`. The proposal focused on three attack surfaces:

> Code audit and pentesting of `f3d` and `libf3d`.
>
> Our primary target is the `libf3d` since its API is used by third-party projects and security issues are more critical.

The scope broke down into three targets: the build system and dependency chain, the plugin/thumbnail subsystem, and file parsing. Of these, file parsing was the most interesting — F3D handles glTF, USD, STL, STEP, PLY, OBJ, FBX, and more. Each format has its own parser, and most of the heavy lifting is delegated to [VTK](https://vtk.org/) (Visualization Toolkit), a massive C++ library originally developed at Kitware for scientific visualization.

The proposal explicitly called out fuzzing campaigns for glTF, USD, and FBX under "Target 3: libf3d: File Parsing and API Security." glTF came first — it's the most widely used format in the set, JSON-based (which makes dictionary fuzzing effective), and VTK's implementation handles a complex web of interlinked structures that practically invites validation bugs.

Six days of audit, one day of reporting — May 30 through July 17, 2025. The fuzzing started on day one.

* * *

## Background

### F3D and VTK

F3D is a desktop 3D viewer: you throw a file at it and it renders. Under the hood, the actual file parsing and rendering pipeline is VTK — a library used far beyond F3D. VTK powers [ParaView](https://www.paraview.org/) (used at Los Alamos National Lab, NASA, and across the energy sector), medical imaging applications, and academic visualization tools. Any memory corruption in VTK's file parsers affects every downstream consumer.

On Linux, F3D also registers as a [thumbnailer](https://f3d.app/doc/user/DESKTOP_INTEGRATION.html) — meaning your file manager will automatically parse 3D files to generate preview thumbnails when you browse a directory. No click required. A malicious `.gltf` file dropped in a shared folder gets parsed the moment someone opens that directory in their file manager.

### The glTF Format

[glTF 2.0](https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html) (GL Transmission Format) is the "JPEG of 3D" — a JSON-based format for transmitting 3D scenes. A glTF file describes a hierarchy of interlinked objects:

```
Scene → Nodes → Meshes → Primitives → Accessors → BufferViews → Buffers
```

Each layer references the next by integer index. An `Accessor` says "read 2549 floats starting at byte offset 20392 from BufferView 1." A `BufferView` says "I'm a window into Buffer 0, starting at byte 20392, length 30588." A `Buffer` points to the raw binary data.

This indirection chain is the attack surface. If any of those integer references are wrong — pointing to a BufferView that's too small, an Accessor that's already been freed, or a Mesh that doesn't exist — the parser will read or write memory it shouldn't. VTK's GLTF loader trusts these references.

### The Import Pipeline

When F3D loads a glTF file, the call chain runs deep through VTK:

```
f3d::scene_impl::add()
  → vtkF3DMetaImporter::Update()
    → vtkImporter::Update()
      → vtkGLTFImporter::ImportBegin()          // phase 1: parse + extract
        → LoadModelMetaDataFromFile()            // parse JSON into internal model
        → LoadModelData()                        // extract binary data via accessors
          → ExtractPrimitiveAccessorData()
            → ExtractPrimitiveAttributes()       // CVE-2025-57106, CVE-2025-57107
      → vtkImporter::ReadData()                  // phase 2: build scene
        → vtkGLTFImporter::ImportActors()        // CVE-2025-57108, CVE-2025-57109
```

Two phases, two bug classes. The buffer overflows (CVE-2025-57106, CVE-2025-57107) live in phase 1 — data extraction from buffers with invalid offsets and counts. The use-after-frees (CVE-2025-57108, CVE-2025-57109) live in phase 2 — the importer accesses model data that was freed between the two phases. In both cases the JSON is valid enough to parse, but the internal references it describes are broken. VTK doesn't catch this until it's already copying memory.

* * *

## Building the Fuzzer

### The cgltf Approach

I didn't start from scratch. The [cgltf](https://github.com/jkuhlmann/cgltf) project — a single-header C glTF parser — already had a [well-documented fuzzing setup](https://deepwiki.com/jkuhlmann/cgltf/8.2-fuzzing) using AFL with a dictionary of glTF keywords. The insight is simple: glTF is structured JSON. A fuzzer that generates random bytes will spend most of its time being rejected by the JSON parser. But a fuzzer armed with a dictionary of valid glTF keywords (`"accessors"`, `"bufferViews"`, `"byteOffset"`, `5126`) can mutate *structurally valid* files into *semantically broken* ones — files that parse as JSON but describe impossible geometry.

I adapted cgltf's AFL dictionary and extended it for VTK's specific extension support:

```
# JSON primitives
"true"
"false"
"null"
"{}"
"[]"

# glTF core keywords
"\"accessors\""
"\"bufferViews\""
"\"byteOffset\""
"\"byteLength\""
"\"componentType\""
"\"count\""

# Component type constants
"5120"    # BYTE
"5121"    # UNSIGNED_BYTE
"5126"    # FLOAT

# Accessor types
"\"SCALAR\""
"\"VEC2\""
"\"VEC3\""
"\"VEC4\""

# Extensions VTK handles
"\"KHR_materials_unlit\""
"\"KHR_texture_basisu\""
"\"KHR_lights_punctual\""
```

The dictionary had 224 entries covering JSON structure, glTF core keywords, component types, accessor types, and extension-specific tokens.

### The Harness

The working harness (`fuzz_f3d_direct.cpp`) is 48 lines. It uses F3D's `createNone()` engine — headless, no GPU — so the fuzzer runs fast without a display server:

```cpp
#include <f3d/engine.h>
#include <f3d/scene.h>
#include <f3d/window.h>
#include <fstream>
#include <filesystem>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 4 || size == 0) return 0;

    // Write fuzz input to a temp file — F3D's API requires file paths
    std::ofstream out("./corpus/temp.gltf", std::ios::binary);
    if (!out) return 0;
    out.write(reinterpret_cast<const char*>(data), size);
    out.close();

    f3d::engine::autoloadPlugins();
    f3d::engine eng = f3d::engine::createNone();

    try {
        eng.getScene().add("./corpus/temp.gltf");
    } catch (const f3d::scene::load_failure_exception& e) {
        return 0;
    } catch (const std::exception& e) {
        return 0;
    }

    try {
        f3d::image img = eng.getWindow().setSize(300, 300)
                             .renderToImage();
    } catch (...) {
    }

    return 0;
}
```

The build uses Clang with libFuzzer and AddressSanitizer:

```cmake
set(FUZZER_FLAGS "-fsanitize=fuzzer,address,undefined")
set(DEBUG_FLAGS "-g" "-O1")

target_compile_options(fuzz_f3d_direct PRIVATE
    ${FUZZER_FLAGS} ${DEBUG_FLAGS})
target_link_options(fuzz_f3d_direct PRIVATE
    ${FUZZER_FLAGS})
```

### Seed Corpus

The corpus started with four valid glTF files of increasing complexity:

- `TriangleWithoutIndices.gltf` — minimal: 1 buffer, 1 accessor, 1 mesh
- `Box.glb` — binary glTF container
- `WaterBottle.gltf` — 5 accessors, 5 buffer views, 4 textures, full PBR material
- `BadBasisU.gltf` — intentionally malformed, exercises the KHR_texture_basisu extension path

The fuzzer mutations focused on the integer fields — accessor indices, byte offsets, counts, component types — while the dictionary ensured the JSON structure stayed parseable. ASAN caught the rest.

* * *

## What Fell Out

Within minutes of the first run, ASAN started flagging crashes. After deduplication and triage, four distinct bug classes emerged — each in a different part of VTK's GLTF import pipeline. All four are triggered by a single malformed `.gltf` file with crafted integer references.

### CVE-2025-57106 — Buffer Overflow in Data Extraction

**Component:** `vtkGLTFDocumentLoader::AccessorLoadingWorker::ExecuteBufferDataExtractionWorker`

The `ExecuteBufferDataExtractionWorker` template function sets up a worker to extract typed data from a buffer:

```cpp
template <typename ComponentType, typename ArrayType, ...>
void ExecuteBufferDataExtractionWorker(
    ArrayType* output, const Accessor& accessor,
    const BufferView& bufferView)
{
    BufferDataExtractionWorker<ComponentType> worker;
    worker.ByteOffset = bufferView.ByteOffset + accessor.ByteOffset;
    worker.ByteStride = bufferView.ByteStride;
    worker.Count = accessor.Count;
    worker.Inbuf = &this->Buffers->operator[](bufferView.Buffer);
    // ...
    vtkArrayDispatch::DispatchByValueType<...>::Execute(output, worker);
}
```

The worker reads `accessor.Count` elements starting at `bufferView.ByteOffset + accessor.ByteOffset` from the buffer. But nothing validates that the buffer actually has that many bytes. A crafted glTF with a `byteLength` of 56 bytes in the BufferView but an accessor claiming 2549 elements reads straight off the end of the heap.

ASAN:
```
heap-buffer-overflow on address 0x5060002903fc
READ of size 4 at 0x5060002903fc thread T0
    #0 ... ExecuteBufferDataExtractionWorker<float, vtkFloatArray, ...>
      vtkGLTFDocumentLoader.cxx:392

0x5060002903fc is located 4 bytes after 56-byte region
```

**CWE:** [CWE-120](https://cwe.mitre.org/data/definitions/120.html) (Buffer Copy without Checking Size of Input)

---

### CVE-2025-57107 — Heap Buffer Overflow in Accessor Copy

**Component:** `vtkGLTFDocumentLoader::Accessor` copy constructor

When `ExtractPrimitiveAttributes` processes mesh attributes, it copies Accessor objects by value:

```cpp
bool vtkGLTFDocumentLoader::ExtractPrimitiveAttributes(
    Primitive& primitive)
{
    // ...
    for (auto& attributePair : primitive.AttributeIndices)
    {
        Accessor accessor =
            this->InternalModel->Accessors[attributePair.second];
        // ...
    }
}
```

The `Accessor` struct (defined at `vtkGLTFDocumentLoader.h:125`) contains fields that reference buffer data. When the accessor's metadata points to memory beyond the allocated region — because the glTF file's accessor indices were mutated to reference an undersized buffer — the compiler-generated copy constructor triggers a `memcpy` that reads past the heap allocation.

ASAN:
```
heap-buffer-overflow on address 0x50d0000435d8
READ of size 21 at 0x50d0000435d8 thread T0
    #0 ... __asan_memcpy
    #1 ... Accessor::Accessor(Accessor const&)
      vtkGLTFDocumentLoader.h:125
    #2 ... ExtractPrimitiveAttributes
      vtkGLTFDocumentLoader.cxx:702

0x50d0000435d8 is located 544 bytes after 136-byte region
```

544 bytes past the end of the allocation — the accessor's index was pointing deep into unrelated heap memory.

**CWE:** [CWE-122](https://cwe.mitre.org/data/definitions/122.html) (Heap-based Buffer Overflow)

---

### CVE-2025-57108 — Use-After-Free in Mesh Copy

**Component:** `vtkGLTFDocumentLoader::Mesh` copy constructor

The `Mesh` struct holds a vector of `Primitive` objects:

```cpp
struct Mesh
{
    std::vector<struct Primitive> Primitives;
    std::vector<float> Weights;
    std::string Name;
};
```

When `ImportActors` copies a mesh from the internal model (line 636: `auto mesh = model->Meshes[node.Mesh]`), the copy constructor needs to read the `Primitives` vector's size. But by this point, the JSON parse tree that owned the mesh data has already been destroyed — `vtknlohmann::json`'s destructor chain (`_Rb_tree::_M_erase`) deallocated the nodes, and the mesh's memory is gone.

ASAN:
```
heap-use-after-free on address 0x507000061818
READ of size 8 at 0x507000061818 thread T0
    #0 ... vector<Primitive>::size()
    #1 ... Mesh::Mesh(Mesh const&)
      vtkGLTFDocumentLoader.h:258
    #2 ... vtkGLTFImporter::ImportActors
      vtkGLTFImporter.cxx:636

0x507000061818 is located 72 bytes inside of 80-byte region
freed by thread T0 here:
    #0 ... operator delete
    #1 ... _Rb_tree::_M_erase  // JSON tree cleanup
```

The mesh struct thinks it's alive. The heap knows otherwise.

**CWE:** [CWE-416](https://cwe.mitre.org/data/definitions/416.html) (Use After Free)

---

### CVE-2025-57109 — Use-After-Free in ImportActors

**Component:** `vtkGLTFImporter::ImportActors`

During scene graph construction, `ImportActors` iterates over nodes and accesses their `Name` member:

```cpp
const auto& node = model->Nodes[nodeId];
// ...
if (!node.Name.empty())
{
    dasmNodeName =
        vtkDataAssembly::MakeValidNodeName(node.Name.c_str());
}
```

The `node.Name.empty()` call at line 623 dereferences the string's internal pointer to check its size. But the node's memory has already been freed — the freed-by trace shows deallocation through the font rasterization path (`stbtt__rasterize` in imgui's `imstb_truetype.h`), which ran during scene setup and reclaimed the heap region that the node data occupied.

ASAN:
```
heap-use-after-free on address 0x5120000e3548
READ of size 8 at 0x5120000e3548 thread T0
    #0 ... string::empty()
    #1 ... vtkGLTFImporter::ImportActors
      vtkGLTFImporter.cxx:623

0x5120000e3548 is located 264 bytes inside of 300-byte region
freed by thread T0 here:
    #0 ... free
    #1 ... stbtt__rasterize  // imgui font rasterizer
```

A string that looks valid, pointing at memory that's been recycled.

**CWE:** [CWE-416](https://cwe.mitre.org/data/definitions/416.html) (Use After Free)

* * *

## Impact

All four vulnerabilities are in VTK's core GLTF import pipeline. Any application that opens untrusted glTF files through VTK is affected — that includes F3D, ParaView, and any custom application built on `libf3d` or VTK's IO modules.

The attack surface is broader than "open a file":

- **Desktop thumbnailers:** F3D registers as a Linux thumbnailer. Browsing a directory containing a malicious `.gltf` triggers the parser with no user interaction beyond opening the file manager.
- **Web-to-desktop pipelines:** glTF is the standard interchange format for 3D content on the web. Files downloaded from model repositories, embedded in emails, or shared via collaboration tools all pass through the same parser.
- **Scientific computing:** ParaView installations at national labs and research institutions process externally-sourced data files routinely.

The buffer overflows (CVE-2025-57106, CVE-2025-57107) are heap reads — information disclosure and crash are guaranteed, code execution is possible with heap grooming but non-trivial. The use-after-frees (CVE-2025-57108, CVE-2025-57109) access freed heap memory that may have been reallocated to attacker-influenced data, making them more directly exploitable in theory.

All four are triggerable with a single malformed `.gltf` file.

**Affected versions:** VTK <= 9.5.0

* * *

## The Fix (or Lack Thereof)

I reported all four bugs to Kitware through responsible disclosure. After some back-and-forth, they asked me to open the issues publicly on VTK's GitLab. I did — all five issues (one CVE maps to two separate code paths) were opened on July 17, 2025:

- [Issue #19732](https://gitlab.kitware.com/vtk/vtk/-/work_items/19732) — CVE-2025-57107 (heap buffer overflow in Accessor copy)
- [Issue #19733](https://gitlab.kitware.com/vtk/vtk/-/work_items/19733) — CVE-2025-57106 (buffer overflow in data extraction, path 1)
- [Issue #19734](https://gitlab.kitware.com/vtk/vtk/-/work_items/19734) — CVE-2025-57106 (buffer overflow in data extraction, path 2)
- [Issue #19735](https://gitlab.kitware.com/vtk/vtk/-/work_items/19735) — CVE-2025-57109 (use-after-free in ImportActors)
- [Issue #19736](https://gitlab.kitware.com/vtk/vtk/-/work_items/19736) — CVE-2025-57108 (use-after-free in Mesh copy)

I proposed fixes and root cause analysis on each issue. The buffer overflows need bounds validation before buffer reads — checking that `bufferView.ByteOffset + accessor.ByteOffset + (accessor.Count * componentSize)` doesn't exceed the buffer's `byteLength`. The use-after-frees need lifetime management fixes to ensure model data isn't freed while still referenced by the import pipeline.

As of this writing — nine months after disclosure — none of the fixes have been merged. The issues remain open. The CVEs remain unpatched in every released version of VTK.

* * *

## Timeline

| Date | Event |
|---|---|
| 2025-05-30 | F3D engagement begins for Radically Open Security |
| 2025-06/07 | Fuzzer built, crashes discovered and triaged into 4 bug classes |
| 2025-07 | Reported to Kitware via responsible disclosure |
| 2025-07-17 | Issues opened publicly on VTK GitLab at Kitware's request ([#19732](https://gitlab.kitware.com/vtk/vtk/-/work_items/19732), [#19733](https://gitlab.kitware.com/vtk/vtk/-/work_items/19733), [#19734](https://gitlab.kitware.com/vtk/vtk/-/work_items/19734), [#19735](https://gitlab.kitware.com/vtk/vtk/-/work_items/19735), [#19736](https://gitlab.kitware.com/vtk/vtk/-/work_items/19736)) |
| 2025-10 | CVE-2025-57106, CVE-2025-57107, CVE-2025-57108, CVE-2025-57109 assigned |
| 2026-04 | Fixes still pending — issues open ~9 months |

* * *

## References

- [VTK GitLab Issue #19732](https://gitlab.kitware.com/vtk/vtk/-/work_items/19732) — CVE-2025-57107, heap buffer overflow in Accessor copy constructor
- [VTK GitLab Issue #19733](https://gitlab.kitware.com/vtk/vtk/-/work_items/19733) — CVE-2025-57106, buffer overflow in data extraction (path 1)
- [VTK GitLab Issue #19734](https://gitlab.kitware.com/vtk/vtk/-/work_items/19734) — CVE-2025-57106, buffer overflow in data extraction (path 2)
- [VTK GitLab Issue #19735](https://gitlab.kitware.com/vtk/vtk/-/work_items/19735) — CVE-2025-57109, use-after-free in ImportActors
- [VTK GitLab Issue #19736](https://gitlab.kitware.com/vtk/vtk/-/work_items/19736) — CVE-2025-57108, use-after-free in Mesh copy
- [CVE-2025-57106](https://www.cve.org/CVERecord?id=CVE-2025-57106) — Buffer Overflow
- [CVE-2025-57107](https://www.cve.org/CVERecord?id=CVE-2025-57107) — Heap Buffer Overflow
- [CVE-2025-57108](https://www.cve.org/CVERecord?id=CVE-2025-57108) — Use-After-Free
- [CVE-2025-57109](https://www.cve.org/CVERecord?id=CVE-2025-57109) — Use-After-Free
- [Snyk — VTK Vulnerabilities](https://security.snyk.io/package/unmanaged/https%3A%2F%2Fgitlab.kitware.com%7Cvtk%2Fvtk)
- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
- [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html)
- [cgltf Fuzzing](https://deepwiki.com/jkuhlmann/cgltf/8.2-fuzzing) — the dictionary-based fuzzing approach that inspired this work
- [glTF 2.0 Specification](https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html)
- [GitHub Advisory GHSA-5pfc-43r5-qrmg](https://github.com/advisories/GHSA-5pfc-43r5-qrmg) (CVE-2025-57106)

* * *

*Responsible disclosure was followed throughout. All issues were reported privately to Kitware before public disclosure.*

*Thanks to [Radically Open Security](https://www.radicallyopensecurity.com/) for the engagement.*
