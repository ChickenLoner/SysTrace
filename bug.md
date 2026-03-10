# Manual Testing Discovery

This file contains a bug and room for improvement found by manually reviews and uses the tool

1. the tool does not escape / show the full name of the file path in command (`rundll32.exe  C:windowsSystem32comsvcs.dll, MiniDump 624 C:templsass.dmp full`) sample -> `sysmon2.json`
2. In process details window, it does not have horizontal scroll so if the command is very long, or the hash is very long, user can not view it
3. The display of End Time "(still running)", Do not confirm that, check for the entire log, if not, there is a chance that the config did not handle this so using word like "Not Detected" or something similar would be more accurate