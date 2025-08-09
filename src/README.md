# Build the Hell's Gate shellcode

```bash
nasm -f bin -o hells_gate.bin hells_gate.asm
```

1. Write the reverse shell shellcode in the `hell.zig` with MAC address obfuscation.
2. Compile the `hell.zig` to a EXE file (this is the file to implement the Hell's Gate).
3. Use [Donut]() to turn it into a shellcode.
4. Use `heaven.zig` to implement the Heaven's Gate.
5. Call the inject function in `heaven.zig` to inject shellcode above.
