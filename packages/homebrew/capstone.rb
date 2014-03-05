require 'formula'

class Capstone < Formula
  homepage 'http://capstone-engine.org'
  url 'http://capstone-engine.org/download/2.1/capstone-2.1.tgz'
  sha1 '3e5fe91684cfc76d73caa857a268332ac9d40659'

  def patches
    # fix pkgconfig path
    "https://github.com/aquynh/capstone/blob/next/packages/homebrew/patch-Makefile-2.1"
  end

  def install
    inreplace 'Makefile', 'lib64', 'lib'
    system "./make.sh"
    ENV["PREFIX"] = prefix
    system "./make.sh", "install"
  end
end
