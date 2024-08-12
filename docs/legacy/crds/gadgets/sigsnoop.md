---
# Code generated by 'make generate-documentation'. DO NOT EDIT.
title: Gadget sigsnoop
---

sigsnoop traces all signals sent on the system.

The following parameters are supported:
- failed: Trace only failed signal sending (default to false).
- signal: Which particular signal to trace (default to all).
- pid: Which particular pid to trace (default to all).
- kill-only: Trace only signals sent by the kill syscall (default to false).


### Example CR

```yaml
apiVersion: gadget.kinvolk.io/v1alpha1
kind: Trace
metadata:
  name: sigsnoop
  namespace: gadget
spec:
  node: ubuntu-hirsute
  gadget: sigsnoop
  runMode: Manual
  outputMode: Stream
  filter:
    namespace: default
```

### Operations


#### start

Start sigsnoop gadget

```bash
$ kubectl annotate -n gadget trace/sigsnoop \
    gadget.kinvolk.io/operation=start
```
#### stop

Stop sigsnoop gadget

```bash
$ kubectl annotate -n gadget trace/sigsnoop \
    gadget.kinvolk.io/operation=stop
```

### Output Modes

* Stream