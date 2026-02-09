# ...moved from root, see previous content...

class AsmNg < Formula
  include Language::Python::Virtualenv

  desc "Open Source Intelligence Automation Tool"
  homepage "https://github.com/0x31i/asm-ng"
  url "https://github.com/0x31i/asm-ng/archive/refs/tags/v5.2.9.tar.gz"
  sha256 "SKIP" # Replace with actual sha256sum for the release tarball
  license "MIT"

  depends_on "python@3.9"
  depends_on "libpq" # For psycopg2-binary

  def install
    virtualenv_install_with_resources

    # Install main scripts as CLI entry points
    bin.install "sf.py" => "asm-ng"
    bin.install "sfcli.py" => "asm-ng-cli"
    bin.install "sfapi.py" => "asm-ng-api"

    # Install all modules, correlations, and spiderfoot code/data
    (libexec/"modules").install Dir["modules/*"]
    (libexec/"correlations").install Dir["correlations/*"]
    (libexec/"spiderfoot").install Dir["spiderfoot/*"]

    # Install all sf* and sflib* files from root
    root_files = Dir["sf*.py", "sflib.py", "sfscan.py", "sfwebui.py"]
    (libexec/"root").install root_files

    # Optionally install man pages if present
    man1.install "packaging/asm-ng.1" if File.exist?("packaging/asm-ng.1")
    man1.install "packaging/asm-ng-cli.1" if File.exist?("packaging/asm-ng-cli.1")
    man1.install "packaging/asm-ng-api.1" if File.exist?("packaging/asm-ng-api.1")
  end

  test do
    system "#{bin}/asm-ng", "--help"
    system "#{bin}/asm-ng-cli", "--help"
    system "#{bin}/asm-ng-api", "--help"
  end
end
