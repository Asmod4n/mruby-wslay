MRuby::Gem::Specification.new('mruby-wslay') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby wrapper for wslay'
  spec.linker.libraries << 'wslay' << 'sodium'
end
