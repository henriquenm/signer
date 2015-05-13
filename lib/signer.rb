require "nokogiri"
require "base64"
require "digest/sha1"
require "openssl"

require "signer/digester"
require "signer/version"

class Signer
  attr_accessor :document, :private_key, :signature_algorithm_id
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

  # Return symbol name for supported digest algorithms and string name for custom ones.
  def digest_algorithm
    @digester.symbol || @digester.digest_name
  end

  # Allows to change algorithm for node digesting (default is SHA1).
  #
  # You may pass either a one of +:sha1+, +:sha256+ or +:gostr3411+ symbols
  # or +Hash+ with keys +:id+ with a string, which will denote algorithm in XML Reference tag
  # and +:digester+ with instance of class with interface compatible with +OpenSSL::Digest+ class.
  def digest_algorithm=(algorithm)
    @digester = Signer::Digester.new(algorithm)
  end

  # Return symbol name for supported digest algorithms and string name for custom ones.
  def signature_digest_algorithm
    @sign_digester.symbol || @sign_digester.digest_name
  end

  # Allows to change digesting algorithm for signature creation. Same as +digest_algorithm=+
  def signature_digest_algorithm=(algorithm)
    @sign_digester = Signer::Digester.new(algorithm)
  end

  # Receives certificate for signing and tries to guess a digest algorithm for signature creation.
  #
  # Will change +signature_digest_algorithm+ and +signature_algorithm_id+ for known certificate types and reset to defaults for others.
  def cert=(certificate)
    @cert = certificate
    # Try to guess a digest algorithm for signature creation
    case @cert.signature_algorithm
      when 'GOST R 34.11-94 with GOST R 34.10-2001'
        self.signature_digest_algorithm = :gostr3411
        self.signature_algorithm_id = 'http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411'
      # Add clauses for other types of keys that require other digest algorithms and identifiers
      else # most common 'sha1WithRSAEncryption' type included here
        self.set_default_signature_method! # Reset any changes as they can become malformed
    end
  end

  def security_token_id
    @security_token_id ||= "uuid-639b8970-7644-4f9e-9bc4-9c2e367808fc-1"
  end

  def security_node
    @security_node.xpath("/*[name()='infNFe']").first# ||= document.xpath('//wsse:Security', wsse: WSSE_NAMESPACE).first
  end

  def canonicalize(node = document, inclusive_namespaces=nil)
    node.canonicalize(Nokogiri::XML::XML_C14N_1_0, inclusive_namespaces, nil) # The last argument should be exactly +nil+ to remove comments from result
  end

  # <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
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

  # <SignedInfo>
  #   <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  #   <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  #   ...
  # </SignedInfo>
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

  # <o:BinarySecurityToken u:Id="" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
  #   ...
  # </o:BinarySecurityToken>
  # <SignedInfo>
  #   ...
  # </SignedInfo>
  # <KeyInfo>
  #   <o:SecurityTokenReference>
  #     <o:Reference ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" URI="#uuid-639b8970-7644-4f9e-9bc4-9c2e367808fc-1"/>
  #   </o:SecurityTokenReference>
  # </KeyInfo>
  # def binary_security_token_node
  #   node = document.at_xpath('wsse:BinarySecurityToken', wsse: WSSE_NAMESPACE)
  #   unless node
  #     node = Nokogiri::XML::Node.new('BinarySecurityToken', document)
  #     node['ValueType']    = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
  #     node['EncodingType'] = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'
  #     node.content = Base64.encode64(cert.to_der).gsub("\n", '')
  #     signature_node.add_previous_sibling(node)
  #     wsse_ns = namespace_prefix(node, WSSE_NAMESPACE, 'wsse')
  #     wsu_ns = namespace_prefix(node, WSU_NAMESPACE, 'wsu')
  #     node["#{wsu_ns}:Id"] = security_token_id
  #     key_info_node = Nokogiri::XML::Node.new('KeyInfo', document)
  #     security_token_reference_node = Nokogiri::XML::Node.new("#{wsse_ns}:SecurityTokenReference", document)
  #     key_info_node.add_child(security_token_reference_node)
  #     reference_node = Nokogiri::XML::Node.new("#{wsse_ns}:Reference", document)
  #     reference_node['ValueType'] = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
  #     reference_node['URI'] = "##{security_token_id}"
  #     security_token_reference_node.add_child(reference_node)
  #     signed_info_node.add_next_sibling(key_info_node)
  #   end
  #   node
  # end

  # <KeyInfo>
  #   <X509Data>
  #     <X509IssuerSerial>
  #       <X509IssuerName>System.Security.Cryptography.X509Certificates.X500DistinguishedName</X509IssuerName>
  #       <X509SerialNumber>13070789</X509SerialNumber>
  #     </X509IssuerSerial>
  #     <X509Certificate>MIID+jCCAuKgAwIBAgIEAMdxxTANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJTRTEeMBwGA1UEChMVTm9yZGVhIEJhbmsgQUIgKHB1YmwpMScwJQYDVQQDEx5Ob3JkZWEgcm9sZS1jZXJ0aWZpY2F0ZXMgQ0EgMDExFDASBgNVBAUTCzUxNjQwNi0wMTIwMB4XDTA5MDYxMTEyNTAxOVoXDTExMDYxMTEyNTAxOVowcjELMAkGA1UEBhMCU0UxIDAeBgNVBAMMF05vcmRlYSBEZW1vIENlcnRpZmljYXRlMRQwEgYDVQQEDAtDZXJ0aWZpY2F0ZTEUMBIGA1UEKgwLTm9yZGVhIERlbW8xFTATBgNVBAUTDDAwOTU1NzI0Mzc3MjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwcgz5AzbxTbsCE51No7fPnSqmQBIMW9OiPkiHotwYQTl+H9qwDvQRyBqHN26tnw7hNvEShd1ZRGUg4drMEXDV5CmKqsAevs9lauWDaHnGKPNHZJ1hNNYXHwymksEz5zMnG8eqRdhb4vOV2FzreJeYpsgx31Bv0aTofHcHVz4uGcCAwEAAaOCASAwggEcMAkGA1UdEwQCMAAwEQYDVR0OBAoECEj6Y9/vU03WMBMGA1UdIAQMMAowCAYGKoVwRwEDMBMGA1UdIwQMMAqACEIFjfLBeTpRMDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYbaHR0cDovL29jc3Aubm9yZGVhLnNlL1JDQTAxMA4GA1UdDwEB/wQEAwIGQDCBiAYDVR0fBIGAMH4wfKB6oHiGdmxkYXA6Ly9sZGFwLm5iLnNlL2NuPU5vcmRlYSUyMHJvbGUtY2VydGlmaWNhdGVzJTIwQ0ElMjAwMSxvPU5vcmRlYSUyMEJhbmslMjBBQiUyMChwdWJsKSxjPVNFP2NlcnRpZmljYXRlcmV2b2NhdGlvbmxpc3QwDQYJKoZIhvcNAQEFBQADggEBAEXUv87VpHk51y3TqkMb1MYDqeKvQRE1cNcvhEJhIzdDpXMA9fG0KqvSTT1e0ZI2r78mXDvtTZnpic44jX2XMSmKO6n+1taAXq940tJUhF4arYMUxwDKOso0Doanogug496gipqMlpLgvIhGt06sWjNrvHzp2eGydUFdCsLr2ULqbDcut7g6eMcmrsnrOntjEU/J3hO8gyCeldJ+fI81qarrK/I0MZLR5LWCyVG/SKduoxHLX7JohsbIGyK1qAh9fi8l6X1Rcu80v5inpu71E/DnjbkAZBo7vsj78zzdk7KNliBIqBcIszdJ3dEHRWSI7FspRxyiR0NDm4lpyLwFtfw=</X509Certificate>
  #   </X509Data>
  # </KeyInfo>
  def x509_data_node
    # issuer_name_node   = Nokogiri::XML::Node.new('X509IssuerName', document)
    # issuer_name_node.content = "System.Security.Cryptography.X509Certificates.X500DistinguishedName"

    # issuer_number_node = Nokogiri::XML::Node.new('X509SerialNumber', document)
    # issuer_number_node.content = cert.serial

    # issuer_serial_node = Nokogiri::XML::Node.new('X509IssuerSerial', document)
    # issuer_serial_node.add_child(issuer_name_node)
    # issuer_serial_node.add_child(issuer_number_node)

    cetificate_node    = Nokogiri::XML::Node.new('X509Certificate', document)
    cetificate_node.content = Base64.encode64(cert.to_der).gsub("\n", '')

    data_node          = Nokogiri::XML::Node.new('X509Data', document)
    # data_node.add_child(issuer_serial_node)
    data_node.add_child(cetificate_node)

    key_info_node      = Nokogiri::XML::Node.new('KeyInfo', document)
    key_info_node.add_child(data_node)

    signed_info_node.add_next_sibling(key_info_node)

    data_node
  end

  ##
  # Digests some +target_node+, which integrity you wish to track. Any changes in digested node will invalidate signed message.
  # All digest should be calculated **before** signing.
  #
  # Available options:
  # * [+:id+]                   Id for the node, if you don't want to use automatically calculated one
  # * [+:inclusive_namespaces+] Array of namespace prefixes which definitions should be added to node during canonicalization
  # * [+:enveloped+]
  #
  # Example of XML that will be inserted in message for call like <tt>digest!(node, inclusive_namespaces: ['soap'])</tt>:
  #
  #   <Reference URI="#_0">
  #     <Transforms>
  #       <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
  #         <ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="soap" />
  #       </Transform>
  #     </Transforms>
  #     <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
  #     <DigestValue>aeqXriJuUCk4tPNPAGDXGqHj6ao=</DigestValue>
  #   </Reference>

  def digest!(target_node, options = {})
    # wsu_ns = namespace_prefix(target_node, WSU_NAMESPACE)
    # current_id = target_node["#{wsu_ns}:Id"]  if wsu_ns
    id = options[:id] || "_#{Digest::SHA1.hexdigest(target_node.to_s)}"
    if id.to_s.size > 0
      # wsu_ns ||= namespace_prefix(target_node, WSU_NAMESPACE, 'wsu')
      # target_node["#{wsu_ns}:Id"] = id.to_s
    end
    # target_node = '<infNFe xmlns="http://www.portalfiscal.inf.br/nfe" Id="NFe51150401882109000162550010000000041784051633" versao="3.10"><ide><cUF>51</cUF><cNF>78405163</cNF><natOp>Venda de mercadoria</natOp><indPag>0</indPag><mod>55</mod><serie>1</serie><nNF>4</nNF><dhEmi>2015-04-30T12:10:00-03:00</dhEmi><dhSaiEnt>2015-04-30T12:10:00-03:00</dhSaiEnt><tpNF>1</tpNF><idDest>1</idDest><cMunFG>5103403</cMunFG><tpImp>1</tpImp><tpEmis>1</tpEmis><cDV>3</cDV><tpAmb>2</tpAmb><finNFe>1</finNFe><indFinal>1</indFinal><indPres>1</indPres><procEmi>0</procEmi><verProc>nfemais.com.br v3</verProc></ide><emit><CNPJ>01882109000162</CNPJ><xNome>COXIPO COM PROD PAPELARIA IMP EXPORTACAO LTDA EPP</xNome><xFant>COXIPO</xFant><enderEmit><xLgr>AVENIDA TENENTE-CORONEL DUARTE</xLgr><nro>191</nro><xBairro>CENTRO NORTE</xBairro><cMun>5103403</cMun><xMun>Cuiaba</xMun><UF>MT</UF><CEP>78005500</CEP><cPais>1058</cPais><xPais>Brasil</xPais><fone>6533171500</fone></enderEmit><IE>130333573</IE><CRT>3</CRT></emit><dest><CNPJ>99999999000191</CNPJ><xNome>NF-E EMITIDA EM AMBIENTE DE HOMOLOGACAO - SEM VALOR FISCAL</xNome><enderDest><xLgr>Rua Test</xLgr><nro>80</nro><xBairro>Vila Test</xBairro><cMun>5103403</cMun><xMun>Cuiaba</xMun><UF>MT</UF><CEP>03978300</CEP><cPais>1058</cPais><xPais>Brasil</xPais><fone>91095751</fone></enderDest><indIEDest>9</indIEDest><email>marculo.henrique@gmail.com</email></dest><det nItem="1"><prod><cProd>008</cProd><cEAN></cEAN><xProd>Test</xProd><NCM>85176130</NCM><EXTIPI>00</EXTIPI><CFOP>5102</CFOP><uCom>UN</uCom><qCom>1.0000</qCom><vUnCom>600.0000000000</vUnCom><vProd>600.00</vProd><cEANTrib></cEANTrib><uTrib>UN</uTrib><qTrib>1.0000</qTrib><vUnTrib>600.0000000000</vUnTrib><indTot>1</indTot><xPed>2</xPed><nItemPed>1</nItemPed></prod><imposto><vTotTrib>185.82</vTotTrib><ICMS><ICMS00><orig>0</orig><CST>00</CST><modBC>0</modBC><vBC>600.00</vBC><pICMS>0.00</pICMS><vICMS>0.00</vICMS></ICMS00></ICMS><PIS><PISAliq><CST>01</CST><vBC>600.00</vBC><pPIS>0.00</pPIS><vPIS>0.00</vPIS></PISAliq></PIS><COFINS><COFINSAliq><CST>01</CST><vBC>600.00</vBC><pCOFINS>0.00</pCOFINS><vCOFINS>0.00</vCOFINS></COFINSAliq></COFINS></imposto></det><total><ICMSTot><vBC>600.00</vBC><vICMS>0.00</vICMS><vICMSDeson>0.00</vICMSDeson><vBCST>0.00</vBCST><vST>0.00</vST><vProd>600.00</vProd><vFrete>0.00</vFrete><vSeg>0.00</vSeg><vDesc>0.00</vDesc><vII>0.00</vII><vIPI>0.00</vIPI><vPIS>0.00</vPIS><vCOFINS>0.00</vCOFINS><vOutro>0.00</vOutro><vNF>600.00</vNF><vTotTrib>185.82</vTotTrib></ICMSTot></total><transp><modFrete>9</modFrete></transp><infAdic><infCpl>description</infCpl></infAdic></infNFe>'
    # target_canon = canonicalize(target_node, options[:inclusive_namespaces])
    puts target_node.to_s.gsub(/\n\r/, '')
    target_digest = OpenSSL::Digest::SHA1.digest(target_node.to_s.gsub(/\n\r/, ''))
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

  ##
  # Sign document with provided certificate, private key and other options
  #
  # This should be very last action before calling +to_xml+, all the required nodes should be digested with +digest!+ **before** signing.
  #
  # Available options:
  # * [+:security_token+]       Serializes certificate in DER format, encodes it with Base64 and inserts it within +<BinarySecurityToken>+ tag
  # * [+:issuer_serial+]
  # * [+:inclusive_namespaces+] Array of namespace prefixes which definitions should be added to signed info node during canonicalization

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

  # Reset digest algorithm for signature creation and signature algorithm identifier
  def set_default_signature_method!
    self.signature_digest_algorithm = :sha1
    self.signature_algorithm_id = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  end

  ##
  # Searches in namespaces, defined on +target_node+ or its ancestors,
  # for the +namespace+ with given URI and returns its prefix.
  #
  # If there is no such namespace and +desired_prefix+ is specified,
  # adds such a namespace to +target_node+ with +desired_prefix+

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
