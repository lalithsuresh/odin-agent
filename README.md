Odin agent
=========

Odin agents run on physical APs, and are implemented as Click elements. Agents contain the logic for the Wi-Fi split-MAC and LVAP handling. Agents also record information about clients using radiotap headers, and communicate with the Odin Master over the Odin control channel. The physical AP hosting the agent also requires a slightly modified Wi-Fi device driver to generate ACK frames for every LVAP that is hosted on the AP.


Source files for Odin agent:

src/odinagent{.cc,.hh}
-----------------

These are the Click OdinAgent element files. They've only been
tested in userspace mode so far. To build:

1. Add these files to <click>/elements/local/

2. Build Click with the --enable-local and --enable-userspace flag.


agent-click-file-gen.py
-----------------------

Click file generator for the agent. Configure and use this script
to generate the appropriate Odin agent click file.
