# Recaster (Ghidra plugin)

## Description

The plugin search dependencies of the variable/parameter and change their names and/or types. See animation below.

![Example of using](./images/example_of_using.gif "Example of using")
> Fig. 1. Example of using the plugin

## Building

Run the following command in a terminal of your choice.

`$ gradle`

## Installation

Launch Ghidra and from the Project Manager go to `File` → `Install Extensions...`. Click the `+` icon near the top right corner of the window. Select the archive with the extension. Restart Ghidra. After restarting the plugin will be installed and ready for use (you will be asked about enabling of the plugin).

## Instruction

1. Find the target: argument of the function.
1. Choose, what you want to change:
    - a variable's name/type ("Recast variable backward") or
    - a parameter of the function ("Recast variable forward").
1. In the context menu click a needed item.

In Tool Options (see Fig. 2) you can change options of the plugin ("Recaster" item):
- source type, which can be overrides;
- name or/and datatype will be changed.

![The plugin's options](./images/options.png)
> Fig. 2. Options of Recaster plugin
