import json
import binascii
f = open("test2.json", "r")
dump = json.load(f)
dump = dump["all"]
dump = [i.get("_source", dict()).get("layers", dict()).get("btatt", dict()).get("btatt.value", "") for i in dump]
dump = ["".join(i.split(":")) for i in dump]
dump = [binascii.unhexlify(i) for i in dump]
dump = [i for i in dump if "Boss:" not in str(i) and "Too cool 4 u" not in str(i) and "Tammy:" not in str(i) and "Bro:" not in str(i) and "John:" not in str(i) and "Mom:" not in str(i)]
ans = b''
for i in dump:
    ans+=i
f = open("test.exe", "wb")
f.write(ans[2:])
f.close()
