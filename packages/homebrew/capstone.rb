require 'formula'

class Capstone < Formula
  homepage 'http://capstone-engine.org'
  url 'http://capstone-engine.org/download/2.1.2/capstone-2.1.2.tgz'
  sha1 'b6bc29593b0d4ca11473f879b6229d01efca408b'

  def install
    # Fixed upstream in next version:
    # https://github.com/aquynh/capstone/commit/dc0d04
    ENV["PREFIX"] = prefix
    ENV["HOMEBREW_CAPSTONE"] = "1"
    system "./make.sh"
    system "./make.sh", "install"
  end
end
