#ripr
---
ripr is a tool that helps you rip out functionality from binary code and use it from python. It accomplishes this by pairing the [Unicorn-Engine](http://www.unicorn-engine.org/) with [Binary Ninja](https://binary.ninja). Currently, `x86`, `x64`, and `arm` are supported and work to a reasonable degree.

### Introduction
---
Reimplementing functionality is a common, often time-consuming, and sometimes arduous process that comes up frequently during reverse engineering. A few examples:

* A CTF challenge has a custom encoding/decoding scheme you need to use in your solution script
* A piece of malware uses a custom hashing or encryption function you need to implement
* You need to make sure your reimplementation behaves _exactly_ as it would on the original architecture

ripr attempts to automatically generate a python class that is functionally identical to a selected piece of code by statically gathering sufficient information and wrapping it all into a "harness" for the unicorn emulator. 

For some concrete examples (that are much easier to grok), check out the `sample` folder!



### Installation
---
The basic process is simple and looks like this:

1. Clone the repo to your local machine
2. Place the `ripr` folder into your Binary Ninja plugins directory

#### Windows
Installation on Windows typically requires installing PyQt5.

1. Follow the steps above
2. `pip2.7.exe install python-qt5`

**Note** ripr assumes your python installation is located at `C:\Python27`. If this is not the case, change the location as appropriate inside `gui.py`.

### Usage
---

#### Packaging a Function
From within Binary Ninja, right click anywhere inside of a function and select `[ripr] Package Function`.

<img src="https://puu.sh/thLAo/491ac39e58.PNG" width="600">

After packaging, a table will appear listing all of the "packages" you have created with ripr during this session:

<img src="https://puu.sh/tnz8C/d0f5141f43.PNG" width="600">

Additionally, ripr will contextualize the packaged function within the GUI.

* Basic Blocks that have been included or identified have their background color darkened
* Instructions that have caused a data dependency to be identified are highlighted Yellow
* Call instructions to imported functions are highlighted Red
* Call instructions to functions inside the target binary are highlighted Blue

This is meant to give the user visual cues about what ripr has seen and automatically identified, making it easier to see "right off the bat" whether manual modification of the package is necessary.

#### Options while packaging
There are a few different prompts which may appear while packaging a function. 

_Code contains calls to Imported Functions. How should this be handled?_

Choosing "Hook" will allow you to write-in your own functionality that runs in lieu of imported functions. Selecting "Nop out Calls" will replace the call instruction with a series of NOPs.

_Target code may depend on outside code. Attempt to map automatically?_

Your selected code contains calls to other functions within the binary. Answering yes will automatically map those functions.

_Use Section Marking Mode for data dependencies?_

Answering yes will map all sections of the binary that are touched by the target code. Answering No will use Page-Marking mode, where every page used by the target code is mapped into emulator memory.

#### Using a ripr "package"
Once a selection of code has been packaged, you will have a python class which encapsulates its functionality. The basic process of using it looks like this:

1. Instantiate the class
2. Call the run() method

Assuming `my_ripped_code` is the class name:

```python
x = my_ripped_code()
y = x.run()
```

All Unicorn functionality is exposed via the `mu` attribute and should work as expected. 

#### Implementing "Imported Calls"
If you choose to hook calls to `imported functions` during the packaging stage, your generated class will contain stub-functions that are called when the imported call would originally have been called.

For example, if your code contained calls to `puts` and `malloc`, the following would be generated in your class:
```python
def hook_puts(self):
    pass
def hook_malloc(self):
    pass
```
Any code you write within these functions will be called in lieu of the actual imported call. If you wanted a reasonable approximation of `puts` (and were emulating x64 code), you could do:

```python
def hook_puts(self):
    arg = self.mu.reg_read(UC_X86_REG_RDI)
    mem = self.mu.mem_read(addr, 0x200)
    print "%s" % (mem.split("\x00")[0])
```

You have full access to all of Unicorn's methods via the `mu` attribute so it is possible to update the emulator context in any way necessary in order to mimic the behavior of a call or perform any actions you'd like instead of the call.

### Function Arguments
Currently, function arguments have to manually be inserted by editing the output of ripr.

For example, in 32 bit x86, function arguments are passed via the stack. The first argument is above the return address and following arguments are above it. So to provide two arguments you could do:

```python
def run(self, arg1,arg2):
    self.mu.reg_write(UC_X86_REG_ESP, 0x7fffffff)
    self.mu.mem_write(0x7fffffff, '\x01\x00\x00\x00')

    self.mu.mem_write(0x80000003, arg1)
    self.mu.mem_write(0x80000007, arg2)
    

    self._start_unicorn(0x80484bb)
    return self.mu.reg_read(UC_X86_REG_EAX)
```

Of course you will have to make sure endianness is correct. Recommend looking into the struct package.


### Code Structure
---
* `packager.py` -- High Level Functionality. Code here drives the process of gathering necessary data.
* `codegen.py`  -- Contains code for actually generating the python output from the gathered data.
* `analysis_engine.py` -- Wraps static analysis engine functionality into a common interface
* `dependency.py` -- Contains code for finding code and data that the target code needs in order to function corrrectly.
* `gui.py` --  A collection of hacks that resembles a user interface
    * Reuses lots of code from the [Binjadock](https://github.com/NOPDev/BinjaDock) project to display results

