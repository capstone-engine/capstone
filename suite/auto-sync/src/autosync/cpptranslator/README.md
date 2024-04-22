<!--
Copyright © 2022 Rot127 <unisono@quyllur.org>
SPDX-License-Identifier: BSD-3
-->

# C++ Translator

Capstone uses source files from LLVM to disassemble opcodes.
Because LLVM is written in C++ we must translate those files to C.

The task of the `CppTranslator` is to do just that.
The translation will not result in a completely correct C file! But it takes away most of the manual work.

## The configuration file

The configuration for each architecture is set in `arch_config.json`.

The config values have the following meaning:

- `General`: Settings valid for all architectures.
   - `diff_color_new`: Color in the `Differ` for translated content.
   - `diff_color_old`: Color in the `Differ` for old/current Capstone content.
   - `diff_color_saved`: Color in the `Differ` for saved content.
   - `diff_color_edited`: Color in the `Differ` for edited content.
   - `patch_editor`: Editor to open for patch editing.
   - `nodes_to_diff`: List of parse tree nodes which get diffed - *Mind the note below*.
      - `node_type`: The `type` of the node to be diffed.
      - `identifier_node_type`: Types of child nodes which identify the node during diffing (the identifier must be the same in the translated and the old file!). Types can be of the form `<parent-type>/<child type>`.
- `<ARCH>`: Settings valid for a specific architecture
   - `files_to_translate`: A list of file paths to translate.
      - `in`: *Path* to a specific source file.
      - `out`: The *filename* of the translated file.
   - `files_for_template_search`: List of file paths to search for calls to template functions.
   - `manually_edite_files`: List of files which are too complicated to translate. The user will be warned about them.
   - `templates_with_arg_deduction`: Template functions which uses [argument deduction](https://en.cppreference.com/w/cpp/language/template_argument_deduction). Those templates are translated to normal functions, not macro definition.

_Note_:
- To understand the `nodes_to_diff` setting, check out `Differ.py`.
- Paths can contain `{AUTO_SYNC_ROOT}`, `{CS_ROOT}` and `{CPP_TRANSLATOR_ROOT}`.
  They are replaced with the absolute paths to those directories.

## Translation process

The translation process simply searches for certain syntax and patches it.

To allow searches for complicated patterns we parse the C++ file with Tree-sitter.
Afterward we can use [pattern queries](https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries)
to find our syntax we would like to patch.

Here is an overview of the procedure:

- First the source file is parsed with Tree-Sitter.
- Afterward the translator iterates of a number of patches.

For each patch we do the following.

```

 Translator                                  Patch
   +---+
   |   |                                     +----+
   |   |  Request pattern to search for      |    |
   |   | ----------------------------------> |    |
   |   |                                     |    |
   |   |  Return pattern                     |    |
   |   | <---------------------------------  |    |
   |   |                                     |    |
   |   | ---+                                |    |
   |   |    | Find                           |    |
   |   |    | captures                       |    |
   |   |    | in src                         |    |
   |   | <--+                                |    |
   |   |                                     |    |
   |   |  Return captures found              |    |
   |   | ----------------------------------> |    |
   |   |                                     |    |
   |   |                                 +-- |    |
   |   |                     Use capture |   |    |
   |   |                     info to     |   |    |
   |   |                     build new   |   |    |
   |   |                     syntax str  |   |    |
   |   |                                 +-> |    |
   |   |                                     |    |
   |   | Return new syntax string to patch   |    |
   |   | <---------------------------------- |    |
   |   |                                     |    |
   |   | ---+                                |    |
   |   |    | Replace old                    |    |
   |   |    | with new syntax                |    |
   |   |    | at all occurrences             |    |
   |   |    | in the file.                   |    |
   |   | <--+                                |    |
   |   |                                     |    |
   +---+                                     +----+
```

## C++ Template translation

Most of the C++ syntax is simple to translate. But unfortunately the one exception are C++ templates.

Translating template functions and calls from C++ to C is tricky.
Since each template has a number of actual implementations we do the following.

- A template function definition is translated into a C macro.
- The template parameters get translated to the macro parameters.
- To differentiate the C implementations, the functions follow the naming pattern `fcn_[template_param_0]_[template_param_1]()`

<hr>

**Example**

This C++ template function

```cpp
template<unsigned X>
void fcn() {
   unsigned a = X * 8;
}
```
becomes
```
#define DEFINE_FCN(X)  \
void fcn ## _ ## X() { \
   unsigned a = X * 8; \
}
```
To define an implementation where `X = 0` we do
```
DEFINE_FCN(0)
```
To call this implementation we call `fcn_0()`.

_(There is a special case when a template parameter is passed on to a template call. But this is explained in the code.)_
<hr>

### Enumerate template instances

In our C++ code a template function can be called with different template parameters.
For each of those calls we need to define a template implementation in C.

To do that we first scan source files for calls to template functions (`TemplateCollector.py` does this).
For each unique call we check the parameter list.
Knowing the parameter list we can now define a C function which uses exactly those parameters.
For the definition we use a macro as above.

<hr>

**Example**

Within this C++ code we see two template function calls:

```cpp
void main() {
   fcn<0>();
   fcn<4>();
}
```
With the knowledge that once parameter `1` and once parameter `4` was passed to the template,
we can define the implementations with the help of our `DEFINE_FCN` macro.
```c
DEFINE_FCN(0)
DEFINE_FCN(4)
```

Within the C code we can now call those with `fcn_0()` and `fcn_4()`.
<hr>
