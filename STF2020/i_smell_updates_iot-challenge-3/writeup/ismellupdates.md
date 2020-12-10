# I smell updates! (16 solves, 1982 points)

## Problem description:
Agent 47, we were able to retrieve the enemy's security log from our QA technician's file! It has come to our attention that the technology used is a 2.4 GHz wireless transmission protocol. We need your expertise to analyse the traffic and identify the communication between them and uncover some secrets! The fate of the world is on you agent, good luck.

Please view this Document for download instructions.

This challenge:
- Unlocks other challenge(s)
- Is eligible for Awesome Write-ups Award

![](/images/problem.PNG)

## Flag format: govtech-csg{derived-value}

## Solution:
Upon downloading the document, we get a file called iot-challenge-3.pcap, a packet capture file.

![](/images/pcap.PNG)

Packet capture files can be opened using WireShark. After opening it, we see the following:

![](/images/openpcap.PNG)

A quick Google search of the protocol shows that we are dealing with Bluetooth.
LE which stands for Low Energy is also an acronym commonly associated to Bluetooth.

However I had no experience dealing with Bluetooth packet captures.
On WireShark's website, we also find that the Bluetooth stack is partially implemented in WireShark. https://wiki.wireshark.org/Bluetooth

Hence, I decided to do the next best thing which was to look through the packets to see if anything interesting stood out.
Luckily, it did not take me long before I found this.

![](/images/texttoexplore.PNG)

ELF is commonly part of the header of an ELF file. 
However, I was still not sure if this was something I had to pursue so I decided to look further.

I then ran into the following:

![](/images/interestingtext.PNG)
![](/images/interestingtext2.PNG)

which I found interesting. This made me think if we have to look at these texts that look like messages.
But then I saw the following:

![](/images/texttoexplore2.PNG)
![](/images/texttoexplore3.PNG)
![](/images/texttoexplore4.PNG)
![](/images/texttoexplore5.PNG)
![](/images/texttoexplore6.PNG)

These were common functions used in C that is part of a libc shared objects file that has probably been placed in this statically linked ELF.

By now, I knew that I was looking at an ELF file that was transmitted over many packets.

A close look also shows that all these packets are from localhost to Raspberr_e0:ad:31. 
In fact, in the info column they all start with "Send Write Request".
This also makes sense if a device is trying to send an updated version of an ELF file over.

But being an inexperienced WireShark user, I had no idea how to stitch the relevant data of the packets back together. 
The ELF file contents also seemed to be interlaced with the text messages.
Furthermore, as there was no TCP stream, I could not just click follow TCP stream and dump the output as follows:

![](/images/followstream.PNG)

Searching online, I also could not find a solution as WireShark has limited support for Bluetooth as mentioned earlier. 
So I tried digging around for a way.

First, I decided to see if I can only make WireShark show me the packets I needed.
I eventually found that I could do so by double clicking on the packet that started with "Send Write Request", before selecting "Apply as Filter" > "Selected".

![](/images/filter1.PNG)
![](/images/filter2.PNG)

This gave me the following output:

![](/images/afterfilter.PNG)
![](/images/afterfilter2.PNG)

As you can see, we only have the packets that start with "Send Write Request".

Now I had to find a way to stitch the data of the packets together, and filter out the few unwanted packets.
After further digging around, I found this:

![](/images/dumpjson.PNG)

By going "File" > "Export Packet Dissections" > "As JSON", I was able to dump the packets into a file. 
After some experimenting, I found that the json format managed to retain all the packet data and was easy to work with, as I could just use Python's json library to manipulate the packets.

So I chose that and exported the packets on display only so that I would not have to filter out packets that does not start with "Send Write Request" again.

![](/images/dumpjson2.PNG)

This gave me a file which I named test2.json. The file looked like this:

![](/images/dumpjson3.PNG)

I could see that this was an array of json objects, with each json object in the array containing the data of one frame.

![](/images/dumpjson4.PNG)

And looking under btatt.value, we can see that it was the same as in WireShark!

![](/images/jsondatacompare.PNG)

This meant that all I had to do was to use a Python script to stitch the packets together as planned.
To read the file, first I placed the whole array into a json object as follows:

![](/images/makejsonobj.PNG)

Then I ran a Python script to obtain the btatt.value data and append them, making sure to remove unwanted data like the text messages and the first packet that started with \x30\x31.
Note that in Bluetooth, the packets are sent directly to the destination, unlike in the internet when packets can take multiple routes.
This means that the packets arrive in the order they were sent.

```python3
import json
import binascii
f = open("test2.json", "r")  # Open json file
dump = json.load(f)  # Load json object into dump
dump = dump["all"]  # Get the list of json objects
dump = [i.get("_source", dict()).get("layers", dict()).get("btatt", dict()).get("btatt.value", "") for i in dump]  # Get a list of the btatt.value for each json object
dump = ["".join(i.split(":")) for i in dump]  # Remove the colons
dump = [binascii.unhexlify(i) for i in dump]  # Convert hex to byte string
dump = [i for i in dump if "Boss:" not in str(i) and "Too cool 4 u" not in str(i) and "Tammy:" not in str(i) and "Bro:" not in str(i) and "John:" not in str(i) and "Mom:" not in str(i)]  # Remove text messages
# Now to append the data together
ans = b''
for i in dump:
    ans+=i
f = open("test.exe", "wb")
f.write(ans[2:])
f.close()
```


Now we get the following file:

![](/images/exegen.PNG)

Seeing that it was an ARM file, I attempted to decompile it using ghidra to see what it did.

![](/images/ghidra3.PNG)
![](/images/ghidra2.PNG)
![](/images/ghidra1.PNG)

This looks like a reverse engineering problem where we must find the input that gets the desired output (In this case, "Authorised!").
This was probably the derived value to place in the flag format.
So I ran the following Python script using the angr library to find the output.
For how to use angr in CTFs: https://docs.angr.io/core-concepts/pathgroups#simple-exploration

```python3
import angr
proj = angr.Project('test.exe')
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"Authorised!" in s.posix.dumps(1))
s = simgr.found
for i in s:
    print(i.posix.dumps(0))
```

![](/images/angr.PNG)

At first, the \x02 byte threw me off, as I was not expecting the flag to contain unprintable characters.
However, looking at the ghidra again, I realised that from the if statement in the first image, we can see that the input should be 8 characters long.
Furthermore, after cleaning up the disassembled code, I realised that only the first 7 characters were checked.
For those new to ghidra, a tip to cleaning up the disassembled code is to fix the length of arrays to acceptable values where necessary as follows:

![](/images/ghidra4.PNG)

This led me to believe the last character was just there to allow the user to use newline to end their input.
This meant that our derived value in the flag is only the first 7 letters.

# Flag
govtech-csg{aNtiB!e}