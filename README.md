
# V8-snapshot-Ghidra-Plugin

**This is not an officially supported Google product.**

This extension supports V8 snapshot binary format from V8 version 8.5.210.20. It is possible that newer versions will not work due to major changes in the format between V8 versions. 

# Installing the extension

* Download the built extension from GitHub
  * Visit the [Releases](../../releases) page, normally use the latest release
  * Download the built extension zip file, the name will be similar to:
    `ghidra_10.1.2_PUBLIC_YYYYMMDD_v8.zip`
* If you don't already have Ghidra, download and install it from
  https://ghidra-sre.org/
* Install the extension into Ghidra
  * Start Ghidra
  * Open `File->Install Extensions...`
  * Press the `+` icon found in the top right of the `Install Extensions` window
  * Navigate to the file location where you downloaded the extension zip file
    above and select it
  * Press `OK`
  * You will be prompted to restart Ghidra for the changes to take effect

# Loading Extension into Eclipse for Development
* Install Java
  * Tested verison: `jdk-17.0.2`
* Install eclipse from [eclipse.org](https://www.eclipse.org/downloads/)
  * Tested version: `2020-06`
* Install Ghidra
  * Tested version: `ghidra_10.1.3_PUBLIC`
  * Ghidra must be started atleast once.
* Install Ghidra Eclipse extension, follow instructions [here](https://ghidra-sre.org/InstallationGuide.html#Extensions)
* Checkout git project `v8-snapshot-ghidra-plugin` to local directory
* In eclipse's `File` menu, select `New->Java Project`
* Un-select `Use default location` and navigate to the `v8-snapshot-ghidra-plugin` folder in the git checkout location
* Press `Next`
* Un-select `Create module-info.java file`
* Press `Finish`
  * There will be build errors
* In the `GhidraDev` menu of Eclipse, use the `Link Ghidra...` and enter the path to the Ghidra binary install location
  * Select the Java project `v8-snapshot-ghidra-plugin` just created
  * If there is Java conflict probably best to keep the current Java by pressing
    `Cancel`
  * Build errors should be resolved
* You can test that everything is working in your project by selecting the `Run` menu, then `Run As` and `Ghidra`.
* A new instance of Ghidra should be loaded, if you import a v8 snapshot, should see the 'V8' Format suggestion in the first entry of the import dialog.

# Updating The Disassembler Specification

* If a change is made to `data/languages/v8bytecode.slaspec`, it needs to be reprocessed by the sleigh utility. Example command: `<ghidra installer folder>/support/sleigh data/languages/v8bytecode.slaspec`

# Build extension from the command line

* Install [gradle](https://gradle.org/)
  * Tested version: `7.4`
* Execute the command from `v8-snapshot-ghidra-plugin` folder
```
$ gradle -PGHIDRA_INSTALL_DIR=<path_to_ghidra>
```
* Zip file will be created in the `dist` folder

# Resources

## Ghidra
* https://ghidra.re/courses/languages/html/sleigh.html

## V8
* V8 source code: https://github.com/v8/v8
* V8 snapshots: https://v8.dev/blog/custom-startup-snapshots
* Other work done to decompile V8 snapshots: https://swarm.ptsecurity.com/how-we-bypassed-bytenode-and-decompiled-node-js-bytecode-in-ghidra/