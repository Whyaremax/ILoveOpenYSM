# Native Anti-Debug And Bootstrap

This note summarizes how the native startup gate was found and what is actually
confirmed about it.

## Short version

- The interesting gate starts before normal runtime use, inside native startup.
- The strongest early anchor is `JNI_OnLoad`, not a later Java UI wrapper.
- The library references launcher/platform/debugger-related strings and low-level
  syscall symbols such as `ptrace`, `prctl`, and `syscall`.
- Dynamic probing shows the native path can load and run, but later bootstrap
  checks still reject incomplete environments.

## How we found it

### 1. Java-side loader anchors

The loader class
`com.elfmcys.yesstevemodel.oOO000O000Ooo00OO0O0O0OO` is the first hard anchor.
It:

- loads the native library with `System.load(...)`
- checks platform/launcher conditions
- references strings such as:
  - `error.yes_steve_model.unsupported_platform`
  - `error.yes_steve_model.unsatisfied_build`
  - `error.yes_steve_model.unsupported_launcher`
  - `error.yes_steve_model.old_launcher`

The startup-gate class
`com.elfmcys.yesstevemodel.o0OOO0O0OO0o0o00OOoOO00O` exposes a native method
that is wrapped by Java and turned into a runtime error if the native side
returns a non-null result.

### 2. Native anchors

The shared library exposes:

- `JNI_OnLoad`
- `JNI_OnUnload`

It also contains strong anti-debug / startup-gate anchors:

- startup-gate JNI signature blobs
- `ptrace`
- `prctl`
- `syscall`
- `/proc/self/exe`
- launcher/runtime strings

Those anchors are why the anti-debug lane was pursued through startup instead of
starting from random export helpers.

### 3. Dynamic proof path

The useful dynamic path was:

- plain `dlopen(...)` harness
- in-process `JNI_CreateJavaVM(...)` harness
- `LD_PRELOAD` interposer logging `dlopen`, `dlsym`, `readlink`, `prctl`,
  `ptrace`, `syscall`, and related calls

That combination avoided leaning too hard on `gdb` in places where the stripped
ELF was inconvenient.

## What is confirmed

- `dlopen` of `libysm-core.so` works
- `JNI_OnLoad` is a real working entrypoint and is reached in a JVM-backed probe
- `JNI_OnLoad` reads `/proc/self/exe`
- low-level guard-related calls such as `prctl(...)` appear during the startup
  path
- if the environment is too incomplete, `JNI_OnLoad` throws and native-method
  registration does not finish

One useful transition was:

- once missing Forge bootstrap pieces such as `ModList` were satisfied, the
  failure shifted deeper instead of dying at the first missing class

That means the problem is not "the library cannot run at all." The problem is
that native startup expects a much more launcher-faithful runtime state.

## What this does not claim

- not a full anti-debug bypass
- not a claim that every guard branch is already mapped
- not a claim that the public repo ships or automates this lane

The important public takeaway is narrower: the anti-debug / startup-gate path is
real, it was found from both Java and native anchors, and `JNI_OnLoad` is the
right place to think about that behavior.
