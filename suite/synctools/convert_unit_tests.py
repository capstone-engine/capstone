import argparse
import os
from glob import glob


def main():
    parser = argparse.ArgumentParser(
        description="Convert LLVM MC unit tests into Capstone MC unit tests"
    )
    parser.add_argument("--arch", required=True, help="Capstone architecture")
    parser.add_argument("--mode", required=True, help="Capstone mode")
    parser.add_argument("--opt", required=True, help="Capstone option")
    parser.add_argument("input", action="store", help="Input folder")
    parser.add_argument("output", action="store", help="Output folder")
    args = parser.parse_args()

    if not os.path.isdir(args.input):
        print("[ERROR] input folder {} does not exist".format(args.output))
        return
    if not os.path.isdir(args.output):
        print("[ERROR] output folder {} does not exist".format(args.output))
        return

    for test_file in glob(os.path.join(args.input, "*.s")):
        print(" > Processing: {}".format(os.path.basename(test_file)))
        lines = []
        with open(test_file) as fp:
            for line in fp.readlines():
                if ("//CHECK:" in line or "// CHECK:" in line) and "// encoding:" in line:
                    parts = line.split("// encoding:")
                    if len(parts) == 2:
                        instrs = parts[0].lstrip("//CHECK:").lstrip("// CHECK:").strip()
                        instrs = " ".join(instrs.split())
                        encoding = parts[1].strip().lstrip("[").rstrip("]")
                        new_line = encoding + " = " + instrs + "\n"
                        lines.append(new_line)
                    else:
                        print("[ERROR] found line bad line: {}".format(line))

        if lines:
            out_file = os.path.join(args.output, os.path.basename(test_file) + ".cs")
            print("  - Writting file: {}".format(out_file))
            with open(out_file, "w") as f:
                f.write("# {}, {}, {}\n".format(args.arch, args.mode, args.opt))
                f.writelines(lines)


if __name__ == "__main__":
    main()
