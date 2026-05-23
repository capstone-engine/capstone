// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3
package org.capstone_engine.cstest;

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import capstone.Capstone;
import capstone.Capstone.CsInsn;

public class TestInput {
    private static final Logger log = Logger.getLogger(TestInput.class.getName());

    private final Map<String, Object> input_dict;
    public final byte[] in_bytes;
    public final List<String> options;
    public final String arch;

    public final String name;
    public final long address;
    public Capstone handle;
    public int arch_bits;

    public TestInput(Map<String, Object> input_dict) {
        this.input_dict = input_dict;
        if (!this.input_dict.containsKey("bytes")) {
            throw new IllegalArgumentException("Error: 'Missing required mapping field'\nField: 'bytes'.");
        }
        if (!this.input_dict.containsKey("options")) {
            throw new IllegalArgumentException("Error: 'Missing required mapping field'\nField: 'options'.");
        }
        if (!this.input_dict.containsKey("arch")) {
            throw new IllegalArgumentException("Error: 'Missing required mapping field'\nField: 'arch'.");
        }
        List<Integer> in_bytes_list = (List<Integer>) this.input_dict.get("bytes");
        this.in_bytes = new byte[in_bytes_list.size()];
        for (int i = 0; i < in_bytes_list.size(); i++) {
            this.in_bytes[i] = in_bytes_list.get(i).byteValue();
        }
        this.options = (List<String>) this.input_dict.get("options");
        this.arch = (String) this.input_dict.get("arch");

        this.name = (String) this.input_dict.getOrDefault("name", "");
        Object address = this.input_dict.getOrDefault("address", 0);
        if (address instanceof Integer) {
            this.address = (Integer) address;
        } else if (address instanceof Long) {
            this.address = (Long) address;
        } else {
            throw new IllegalArgumentException("Error: 'Invalid type'\nField: 'address'.");
        }
        this.handle = null;
        this.arch_bits = 0;
    }

    public void setup() {
        log.fine("Init " + this);
        Integer arch = App.getCsIntAttr(this.arch, "CS_ARCH", false);
        if (arch == null)
            arch = App.getCsIntAttr("CS_ARCH_" + this.arch.toUpperCase(), "CS_ARCH", false);
        if (arch == null)
            throw new IllegalArgumentException("Couldn't init architecture as '" + this.arch + "' or 'CS_ARCH_" + this.arch.toUpperCase() + "'.\n'" + this.arch + "' is not mapped to a capstone architecture.");
        
        int new_mode = 0;
        for (String opt : this.options) {
            if (opt.contains("CS_MODE_")) {
                Integer mode = App.getCsIntAttr(opt, "CS_OPT");
                if (mode != null)
                    new_mode |= mode;
            }
        }
        this.handle = new Capstone(arch, new_mode);

        for (String opt : this.options) {
            if (opt.isEmpty()) {
                continue;
            }
            if (opt.contains("CS_MODE_")) {
                continue;
            }
            if (opt.contains("CS_OPT_") && App.configs.containsKey(opt)) {
                int mtype = App.configs.get(opt).get("type");
                int val = App.configs.get(opt).get("val");
                this.handle.setOption(mtype, val);
                continue;
            }
            log.warning("Option: '" + opt + "' not used");
        }

        this.arch_bits = App.archBits(this.handle.arch, this.handle.mode);
        log.fine("Init done");
    }

    public CsInsn[] decode() {
        if (this.handle == null) {
            throw new IllegalStateException("handle is null. Must be setup before.");
        }
        return this.handle.disasm(this.in_bytes, this.address);
    }

    @Override
    public String toString() {
        StringBuilder bytesStr = new StringBuilder();
        for (byte b : this.in_bytes) {
            bytesStr.append(String.format("0x%02x, ", b));
        }
        String defaultStr = String.format(
            "TestInput { arch: %s, options: %s, addr: 0x%x, bytes: [ %s] }",
            this.arch, this.options, this.address, bytesStr.toString()
        );
        if (!this.name.isEmpty()) {
            return this.name + " -- " + defaultStr;
        }
        return defaultStr;
    }
}
