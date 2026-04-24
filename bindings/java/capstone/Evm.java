// Capstone Java binding
// Copyright © 2025 Peace-Maker <peacemakerctf@gmail.com>
// SPDX-License-Identifier: BSD-3

package capstone;

import com.sun.jna.Structure;
import com.sun.jna.Union;

import java.util.List;
import java.util.Arrays;

import static capstone.Evm_const.*;

public class Evm {

  
  public static class UnionOpInfo extends Capstone.UnionOpInfo {
    public byte pop;
    public byte push;
    public int fee;

    @Override
    public List<String> getFieldOrder() {
      return Arrays.asList("pop", "push", "fee");
    }
  }

  public static class OpInfo extends Capstone.OpInfo {
    public byte pop;
    public byte push;
    public int fee;

    public OpInfo(UnionOpInfo op_info) {
      pop = op_info.pop;
      push = op_info.push;
      fee = op_info.fee;
    }
  }
}
