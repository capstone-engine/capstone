<!--
Copyright © 2024 Rot127 <unisono@quyllur.org>
SPDX-License-Identifier: BSD-3
-->

## Building

`cstest` is build together with Capstone by adding the flag `-DCAPSTONE_BUILD_CSTEST`.

The build requires `libyaml`. It is a fairly common package and should be provided by your package manager.

## Testing

Files to test `cstest` itself are located in `suite/cstest/test`
