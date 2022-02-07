# emu_ida  

Code emulator plugin for IDA Pro (v 0.0.6)  

The plugin is designed for simple data decryption and getting stack strings.  

## Requirements  
Emulator Unicorn  
pip install -r requirements.txt  
or  
pip install unicorn  

## Install 
Copy emu_ida.py into directory C:\Program Files\<IDA Pro 7.x>\plugins  

## Usage  
Select the area of the code to be executed and run the plugin using the context menu or Alt-E.  
The result will be written to comments and dump files in the current directory.  
Memory addresses can be null :-)  
