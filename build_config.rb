MRuby::Build.new do |conf|
  # Detect host OS
  host_os = RbConfig::CONFIG['host_os']
  is_windows = host_os =~ /mswin|mingw|cygwin/
  is_macos = host_os =~ /darwin/

  conf.toolchain :clang

  # Common flags
  conf.enable_debug
  conf.enable_test
  conf.cxx.flags << '-fno-omit-frame-pointer' << '-g' << '-ggdb'
  conf.cc.flags << '-fno-omit-frame-pointer' << '-g' << '-ggdb'

  # Enable sanitizers only on POSIX platforms
  unless is_windows
   conf.enable_sanitizer "address,undefined"
  end

  # macOS-specific header paths (Apple Clang & SDK)
  if is_macos
    sdk_path = `xcrun --show-sdk-path`.strip
    std_include = "#{sdk_path}/usr/include/c++/v1"
    if File.directory?(std_include)
      conf.cxx.include_paths << std_include
      conf.cxx.flags << "-isystem" << std_include
      conf.cxx.flags << "-isysroot" << sdk_path
    else
      puts "⚠️ Missing macOS libc++ headers at #{std_include}"
    end
  end

  conf.gembox 'full-core'
  conf.gem File.expand_path(File.dirname(__FILE__))
end
