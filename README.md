# fornesic-data-from-registry
An attempt to automate the process of fetching information from registry keys that can be utilized from forensics point of view. 

The script utilises the knowledge shared here: [Digital Forensics, Part 5: Analyzing the Windows Registry for Evidence](https://www.hackers-arise.com/post/2016/10/21/digital-forensics-part-5-analyzing-the-windows-registry-for-evidence)

Aim is to save the time and efforts needed to go through all those keys for information.

_Better to run Powershell as admin & set execution policy to unrestricted or bypass to allow the script to get executed_

### Right now, the script fetches output for:
- Wireless Access Points
- URLs visited in the Internet Explorer
- Interface related data
- Start Up information
- Run Once Start Up Information
- Legacy Application Information
- Mounted Devices Information
- Recent Documents Information

### To-Do
- [ ] Support for some special characters
- [ ] Inclusion of Sysinternals tools for more data 
