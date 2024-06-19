[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

Please, note well: this file and the scaffold were generated from [a
template](https://github.com/kubewarden/rust-policy-template). Make
this project yours!

You can use `cargo generate -g https://github.com/kubewarden/rust-policy-template.git`
to create your Policy from this template.

# Kubewarden policy disallow-privileged-policy

## Description

This policy will reject pods that have a name `invalid-pod-name`. If
the pod to be validated has a different name, or if a different type
of resource is evaluated, it will be accepted.

## Settings

This policy has no configurable settings. This would be a good place
to document if yours does, and what behaviors can be configured by
tweaking them.

## License

```
Copyright (C) 2021 shilazi <nilprobe@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
