require 'minitest/autorun'
require_relative '../lib/ebics'

class SchemaTest < MiniTest::Unit::TestCase
  def setup
    @user = EBICS::User.new do |key|
      key.rsa = OpenSSL::X509::Certificate.new File.read('../keys/example.cer')
    end

    @example_key = @user.key('example')
  end

  def test_key_digest
    assert_equal @example_key.public_exponent, 'AQAB'
    assert_equal @example_key.public_sha_256.upcase, "F5ACB7B5CF88DCC80905AAE8783ED725F3AD1DCABB211DB77E58D679F9747739"
  end

  def test_public_modulus
    assert_equal Base64.strict_decode64(@example_key.public_modulus), 'D78E68ED9F1E5E7A6BB6DC4B81409DF4F2BC68A26E68B279DF49C75C227C2A23BB3CCBA674955A76C39B6C32075FD85CAD55FDC9652BE2C2ADABF8F31327A206B4691715C6B482B69016F8F07A5A7D612A4356DA6FF022E3F5560F8B076100B0056F0A232B0A9C86294506350E71D0F87DD77C58520678D51ABF08D276C3802DB8281BAF92AF453C2F284BF8244279AB299E76ADD8CB592DEADE476D090BCCCA4C381B4C2F350189952FD6C4C0A44B4ADFD09D088F06004B19756E5E3D276BEFBCB4AAC03B4024F15A588BA4D0C1C7804EB98273F4875E8EAB4D4F8CC00FBB1007A61A8B9E0BCC9D25A47980DDB68ADFF63780126AC42DD61D205FEBCC7AEA27'
  end
end
