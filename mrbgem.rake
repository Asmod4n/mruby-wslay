MRuby::Gem::Specification.new('mruby-wslay') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby wrapper for wslay'
  spec.add_dependency 'mruby-sysrandom'
  spec.add_dependency 'mruby-errno'
  spec.add_dependency 'mruby-struct'
  spec.add_dependency 'mruby-string-is-utf8'
end
