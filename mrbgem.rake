MRuby::Gem::Specification.new('mruby-wslay') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby wrapper for wslay'
  spec.add_dependency 'mruby-sysrandom'
  spec.add_dependency 'mruby-errno'
  spec.add_dependency 'mruby-struct'
  spec.add_dependency 'mruby-string-is-utf8'

  if spec.cc.respond_to? :search_header_path
    spec.cc.defines << 'HAVE_ARPA_INET_H' if spec.cc.search_header_path 'arpa/inet.h'
    spec.cc.defines << 'HAVE_NETINET_IN_H' if spec.cc.search_header_path 'netinet/in.h'
    spec.cc.defines << 'HAVE_WINSOCK2_H' if spec.cc.search_header_path 'winsock2.h'
  end
end
