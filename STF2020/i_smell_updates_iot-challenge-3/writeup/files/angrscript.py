import angr
proj = angr.Project('test.exe')
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"Authorised!" in s.posix.dumps(1))
s = simgr.found
for i in s:
    print(i.posix.dumps(0))
