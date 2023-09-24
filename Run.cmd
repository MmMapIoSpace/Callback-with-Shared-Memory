set DriverPath="E:\Repositories\Callback with Shared Memory\x64\Release\Driver.sys"

sc create CsmDriver type=kernel binPath=%DriverPath%
sc start CsmDriver
pause
sc stop CsmDriver
sc delete CsmDriver