MRuby::Gem::Specification.new('mruby-wslay') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby wrapper for wslay'
  spec.add_dependency 'mruby-sysrandom'
  spec.add_dependency 'mruby-errno'
  spec.add_dependency 'mruby-struct'
  spec.add_dependency 'mruby-string-is-utf8'

  if spec.cxx.search_header_path('wslay/wslay.h')
    spec.linker.libraries << 'wslay'
  else
    if spec.cc.respond_to? :search_header_path
      spec.cc.defines << 'HAVE_ARPA_INET_H' if spec.cc.search_header_path 'arpa/inet.h'
      spec.cxx.defines << 'HAVE_ARPA_INET_H' if spec.cxx.search_header_path 'arpa/inet.h'
      spec.cc.defines << 'HAVE_NETINET_IN_H' if spec.cc.search_header_path 'netinet/in.h'
      spec.cxx.defines << 'HAVE_NETINET_IN_H' if spec.cxx.search_header_path 'netinet/in.h'
      spec.cc.defines << 'HAVE_WINSOCK2_H' if spec.cc.search_header_path 'winsock2.h'
      spec.cxx.defines << 'HAVE_WINSOCK2_H' if spec.cxx.search_header_path 'winsock2.h'
    end
    wslay_src = "#{spec.dir}/deps/wslay/lib"
    spec.cc.include_paths << "#{wslay_src}/includes"
    spec.cxx.include_paths << "#{wslay_src}/includes"

    # Expose wslay's own public header the same way the system-wslay
    # branch above already does implicitly (a system header is on every
    # gem's search path for free). Every mrbgem's own include/ directory
    # is visible to every *other* gem unconditionally - copying the
    # vendored header there is enough for a dependent gem (webmachine-mruby)
    # to `#include <wslay/wslay.h>` and call wslay_frame_context_init /
    # wslay_frame_write / wslay_frame_recv directly in its own C++, no
    # Ruby-level API needed for the frame layer (see wslay_frame.h's
    # struct wslay_frame_context staying opaque here - only the pointer
    # typedef and function declarations are in this public header, so
    # nothing else needs vendoring alongside it).
    #
    # wslay.h itself #includes wslay/wslayver.h, which upstream ships only
    # as an autotools .in template (@PACKAGE_VERSION@ substituted by
    # `configure`, which never runs here) - materialize it the same way,
    # once, with the version string this gem already uses. Single source
    # of truth: this replaces the old separate WSLAY_VERSION -D define
    # below, which would otherwise redefine the same macro a second time.
    exposed_header_dir = "#{spec.dir}/include/wslay"
    FileUtils.mkdir_p exposed_header_dir
    FileUtils.cp "#{wslay_src}/includes/wslay/wslay.h", exposed_header_dir
    wslayver_in = File.read("#{wslay_src}/includes/wslay/wslayver.h.in")
    File.write("#{exposed_header_dir}/wslayver.h", wslayver_in.sub('@PACKAGE_VERSION@', '1.0.1-dev'))
    source_files = %W(
      #{wslay_src}/wslay_event.c
      #{wslay_src}/wslay_frame.c
      #{wslay_src}/wslay_net.c
      #{wslay_src}/wslay_queue.c
    )
    spec.objs += source_files.map { |f| f.relative_path_from(dir).pathmap("#{build_dir}/%X#{spec.exts.object}" ) }
  end
end
