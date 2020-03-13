# diFUSE
Distributed file system written in python using libfuse api.

## run

for bootstrap:<br>
    ``` python bootstrap.py
    ```
    by default it listens on 0.0.0.0:8081

for server:<br>
    ``` python server.py ip 8081 
    ```
    ip and port correspond to ip of bootstrap node to connect to.

for client:<br>
    ``` python client.py mountpoint
    ```
    just run in the same machine as the server, it would connect through localhost.

by default it will save files in difuse.local in the local directory, directory must exist and be empty prior to execution.
