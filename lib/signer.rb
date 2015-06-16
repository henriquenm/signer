require "nokogiri"
require "base64"
require "digest/sha1"
require "openssl"

require "signer/digester"
require "signer/version"

class Signer
  attr_accessor :document, :private_key, :signature_algorithm_id, :service
  attr_reader :cert
  attr_writer :security_node, :signature_node, :security_token_id

  WSU_NAMESPACE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
  WSSE_NAMESPACE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'

  def initialize(document)
    self.document = Nokogiri::XML(document.to_s, &:noblanks)
    self.digest_algorithm = :sha1
    self.set_default_signature_method!
  end

  def to_xml
    document.to_xml(:save_with => 0)
  end

  def digest_algorithm
    @digester.symbol || @digester.digest_name
  end

  def digest_algorithm=(algorithm)
    @digester = Signer::Digester.new(algorithm)
  end

  def signature_digest_algorithm
    @sign_digester.symbol || @sign_digester.digest_name
  end

  def signature_digest_algorithm=(algorithm)
    @sign_digester = Signer::Digester.new(algorithm)
  end

  def cert=(certificate)
    @cert = certificate
    case @cert.signature_algorithm
      when 'GOST R 34.11-94 with GOST R 34.10-2001'
        self.signature_digest_algorithm = :gostr3411
        self.signature_algorithm_id = 'http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411'
      else
        self.set_default_signature_method!
    end
  end

  def security_token_id
    @security_token_id ||= "uuid-639b8970-7644-4f9e-9bc4-9c2e367808fc-1"
  end

  def security_node
    if service == :authorize
      @security_node.xpath("/*[name()='NFe']").first
    elsif service == :cancelation
      @security_node.xpath("/*[name()='evento']").first
    elsif service == :numeric_disable
      @security_node.xpath("/*[name()='inutNFe']").first
    end
  end

  def canonicalize(node = document, inclusive_namespaces=nil)
    node.canonicalize(Nokogiri::XML::XML_C14N_1_0, inclusive_namespaces, nil)
  end

  def signature_node
    @signature_node ||= begin
      @signature_node = security_node.at_xpath('ds:Signature', ds: 'http://www.w3.org/2000/09/xmldsig#')
      unless @signature_node
        @signature_node = Nokogiri::XML::Node.new('Signature', document)
        @signature_node.default_namespace = 'http://www.w3.org/2000/09/xmldsig#'
        security_node.add_child(@signature_node)
      end
      @signature_node
    end
  end

  def signed_info_node
    node = signature_node.at_xpath('ds:SignedInfo', ds: 'http://www.w3.org/2000/09/xmldsig#')
    unless node
      node = Nokogiri::XML::Node.new('SignedInfo', document)
      signature_node.add_child(node)
      canonicalization_method_node = Nokogiri::XML::Node.new('CanonicalizationMethod', document)
      canonicalization_method_node['Algorithm'] = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
      node.add_child(canonicalization_method_node)
      signature_method_node = Nokogiri::XML::Node.new('SignatureMethod', document)
      signature_method_node['Algorithm'] = self.signature_algorithm_id
      node.add_child(signature_method_node)
    end
    node
  end

  def x509_data_node
    cetificate_node    = Nokogiri::XML::Node.new('X509Certificate', document)
    cetificate_node.content = Base64.encode64(cert.to_der).gsub("\n", '')

    data_node          = Nokogiri::XML::Node.new('X509Data', document)
    data_node.add_child(cetificate_node)

    key_info_node      = Nokogiri::XML::Node.new('KeyInfo', document)
    key_info_node.add_child(data_node)

    signed_info_node.add_next_sibling(key_info_node)

    data_node
  end

  def digest!(target_node, options = {})
    id = options[:id] || "_#{Digest::SHA1.hexdigest(target_node.to_s)}"

    if service == :numeric_disable
      target_digest.gsub("infInut Id", "infInut xmlns=\"http://www.portalfiscal.inf.br/nfe\" Id")
    end

    target_digest = OpenSSL::Digest::SHA1.digest(target_node)
    target_digest = Base64.encode64(target_digest.to_s).gsub(/\n/, '')

    reference_node = Nokogiri::XML::Node.new('Reference', document)
    reference_node['URI'] = id.to_s.size > 0 ? "##{id}" : ""
    signed_info_node.add_child(reference_node)

    transforms_node = Nokogiri::XML::Node.new('Transforms', document)
    reference_node.add_child(transforms_node)

    transform_node_1 = Nokogiri::XML::Node.new('Transform', document)
    transform_node_2 = Nokogiri::XML::Node.new('Transform', document)
    if options[:enveloped]
      transform_node_1['Algorithm'] = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
      transform_node_2['Algorithm'] = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
    else
      transform_node_1['Algorithm'] = 'http://www.w3.org/2001/10/xml-exc-c14n#'
    end
    if options[:inclusive_namespaces]
      inclusive_namespaces_node = Nokogiri::XML::Node.new('ec:InclusiveNamespaces', document)
      inclusive_namespaces_node.add_namespace_definition('ec', transform_node['Algorithm'])
      inclusive_namespaces_node['PrefixList'] = options[:inclusive_namespaces].join(' ')
      transform_node_1.add_child(inclusive_namespaces_node)
      transform_node_2.add_child(inclusive_namespaces_node)
    end
    transforms_node.add_child(transform_node_1)
    transforms_node.add_child(transform_node_2)

    digest_method_node = Nokogiri::XML::Node.new('DigestMethod', document)
    digest_method_node['Algorithm'] = @digester.digest_id
    reference_node.add_child(digest_method_node)

    digest_value_node = Nokogiri::XML::Node.new('DigestValue', document)
    digest_value_node.content = target_digest
    reference_node.add_child(digest_value_node)
    self
  end

  def sign!(options = {})
    if options[:security_token]
      binary_security_token_node
    end

    if options[:issuer_serial]
      x509_data_node
    end

    if options[:inclusive_namespaces]
      c14n_method_node = signed_info_node.at_xpath('ds:CanonicalizationMethod', ds: 'http://www.w3.org/2000/09/xmldsig#')
      inclusive_namespaces_node = Nokogiri::XML::Node.new('ec:InclusiveNamespaces', document)
      inclusive_namespaces_node.add_namespace_definition('ec', c14n_method_node['Algorithm'])
      inclusive_namespaces_node['PrefixList'] = options[:inclusive_namespaces].join(' ')
      c14n_method_node.add_child(inclusive_namespaces_node)
    end

    signed_info_canon = canonicalize(signed_info_node, options[:inclusive_namespaces])

    signature = private_key.sign(@sign_digester.digester, signed_info_canon)
    signature_value_digest = Base64.encode64(signature).gsub("\n", '')

    signature_value_node = Nokogiri::XML::Node.new('SignatureValue', document)
    signature_value_node.content = signature_value_digest
    signed_info_node.add_next_sibling(signature_value_node)
    self
  end

  protected

  def set_default_signature_method!
    self.signature_digest_algorithm = :sha1
    self.signature_algorithm_id = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  end

  def namespace_prefix(target_node, namespace, desired_prefix = nil)
    ns = target_node.namespaces.key(namespace)
    if ns
      ns.match(/(?:xmlns:)?(.*)/) && $1
    elsif desired_prefix
      target_node.add_namespace_definition(desired_prefix, namespace)
      desired_prefix
    end
  end

end
