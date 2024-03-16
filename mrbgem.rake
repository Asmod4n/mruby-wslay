MRuby::Gem::Specification.new('mruby-wslay') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby wrapper for wslay'
  spec.add_dependency 'mruby-sysrandom'
  spec.add_dependency 'mruby-errno'
  spec.add_dependency 'mruby-struct'
  spec.add_dependency 'mruby-string-is-utf8'

  if spec.cc.search_header_path('wslay/wslay.h')
    spec.linker.libraries << 'wslay'
  else
    if spec.cc.respond_to? :search_header_path
      spec.cc.defines << 'HAVE_ARPA_INET_H' if spec.cc.search_header_path 'arpa/inet.h'
      spec.cc.defines << 'HAVE_NETINET_IN_H' if spec.cc.search_header_path 'netinet/in.h'
      spec.cc.defines << 'HAVE_WINSOCK2_H' if spec.cc.search_header_path 'winsock2.h'
    end
    spec.cc.defines << 'WSLAY_VERSION=1.0.1-dev'
    wslay_src = "#{spec.dir}/deps/wslay/lib"
    spec.cc.include_paths << "#{wslay_src}/includes"
    source_files = %W(
      #{wslay_src}/wslay_event.c
      #{wslay_src}/wslay_frame.c
      #{wslay_src}/wslay_net.c
      #{wslay_src}/wslay_queue.c
    )
    spec.objs += source_files.map { |f| f.relative_path_from(dir).pathmap("#{build_dir}/%X#{spec.exts.object}" ) }
  end
end
