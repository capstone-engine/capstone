require 'formula'

class Capstone < Formula
  homepage 'http://capstone-engine.org'
  url 'http://capstone-engine.org/download/3.0/capstone-3.0.tgz'
  sha1 '235ceab369025fbad9887fe826b741ca84b1ab41'

  def install
    # Fixed upstream in next version:
    # https://github.com/aquynh/capstone/commit/xxxx
    ENV["PREFIX"] = prefix
    ENV["HOMEBREW_CAPSTONE"] = "1"
    system "./make.sh"
    system "./make.sh", "install"
  end
end
