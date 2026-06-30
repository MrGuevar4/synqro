Pod::Spec.new do |s|
  s.name             = 'synqro'
  s.version          = '0.1.0'
  s.summary          = 'Synqro Zero-Trust OTA Updater library'
  s.description      = <<-DESC
Synqro is a zero-trust over-the-air (OTA) software update engine built in Rust.
It provides secure update distribution across multiple platforms.
                       DESC
  s.homepage         = 'https://github.com/MrGuevar4/synqro'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Farhang Fatih' => 'farhangfatih211@gmail.com' }
  s.source           = { :git => 'https://github.com/MrGuevar4/synqro.git', :tag => "v#{s.version}" }

  s.ios.deployment_target = '13.0'
  s.vendored_libraries = 'target/release/libsynqro.a'
  s.source_files = 'ffi/synqro.h'
  s.public_header_files = 'ffi/synqro.h'
  
  s.pod_target_xcconfig = { 'STRIP_INSTALLED_PRODUCT' => 'YES' }
end
