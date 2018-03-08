package main.java.com.ibm.appid.saml.perf;

import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.Random;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.*;
import org.xml.sax.InputSource;

/**
 * This is a simple example of generating an Enveloped XML
 * Signature using the JSR 105 API. The resulting signature will look
 * like (key and signature values will be different):
 *
 * <pre><code>
 *<Envelope xmlns="urn:envelope">
 * <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
 *   <SignedInfo>
 *     <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n
 -20010315"/>
 *     <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
 *     <Reference URI="">
 *       <Transforms>
 *         <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
 *       </Transforms>
 *       <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
 *       <DigestValue>K8M/lPbKnuMDsO0Uzuj75lQtzQI=<DigestValue>
 *     </Reference>
 *   </SignedInfo>
 *   <SignatureValue>
 *     DpEylhQoiUKBoKWmYfajXO7LZxiDYgVtUtCNyTgwZgoChzorA2nhkQ==
 *   </SignatureValue>
 *   <KeyInfo>
 *     <KeyValue>
 *       <DSAKeyValue>
 *         <P>
 *           rFto8uPQM6y34FLPmDh40BLJ1rVrC8VeRquuhPZ6jYNFkQuwxnu/wCvIAMhukPBL
 *           FET8bJf/b2ef+oqxZajEb+88zlZoyG8g/wMfDBHTxz+CnowLahnCCTYBp5kt7G8q
 *           UobJuvjylwj1st7V9Lsu03iXMXtbiriUjFa5gURasN8=
 *         </P>
 *         <Q>
 *           kEjAFpCe4lcUOdwphpzf+tBaUds=
 *         </Q>
 *         <G>
 *           oe14R2OtyKx+s+60O5BRNMOYpIg2TU/f15N3bsDErKOWtKXeNK9FS7dWStreDxo2
 *           SSgOonqAd4FuJ/4uva7GgNL4ULIqY7E+mW5iwJ7n/WTELh98mEocsLXkNh24HcH4
 *           BZfSCTruuzmCyjdV1KSqX/Eux04HfCWYmdxN3SQ/qqw=
 *         </G>
 *         <Y>
 *           pA5NnZvcd574WRXuOA7ZfC/7Lqt4cB0MRLWtHubtJoVOao9ib5ry4rTk0r6ddnOv
 *           AIGKktutzK3ymvKleS3DOrwZQgJ+/BDWDW8kO9R66o6rdjiSobBi/0c2V1+dkqOg
 *           jFmKz395mvCOZGhC7fqAVhHat2EjGPMfgSZyABa7+1k=
 *         </Y>
 *       </DSAKeyValue>
 *     </KeyValue>
 *   </KeyInfo>
 * </Signature>
 *</Envelope>
 * </code></pre>
 */
public class XMLSigning {
    private static Random random = new Random();

    //
    // Synopsis: java GenEnveloped [document] [output]
    //
    //    where "document" is the name of a file containing the XML document
    //    to be signed, and "output" is the name of the file to store the
    //    signed document. The 2nd argument is optional - if not specified,
    //    standard output will be used.
    //
    public static void main(String[] args) throws Exception {

        /**
         * <?xml version="1.0"?><AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_5ae3a983880e51913cc5cf7e5ab1bfbf4a1580352d" IssueInstant="2018-03-01T16:13:26.583Z" Destination="https://example.com/saml2/sso-redirect/706634" AssertionConsumerServiceURL="https://appid-oauth.stage1.eu-gb.bluemix.net/saml2/v1/5077e19f-6c0e-444b-91e3-fba2dc1affd8/login-acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ForceAuthn="true"><saml:Issuer>urn:ibm:cloud:services:appid:5077e19f-6c0e-444b-91e3-fba2dc1affd8</saml:Issuer><NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/><RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></RequestedAuthnContext></AuthnRequest>
         */
        String samlReq = "jVNLj9owEP4rke95mBAIVsiKgqoibVsEtIdeKseesJYSO%2FU4LP33dQKoHLarniKNxt98rxRPl7YJzmBRGb0kNErIU1msevei9%2FCrB3SBX9C4JL3VzHBUyDRvAZkT7LD6%2FMwmUcI6a5wRpiHXZYa8bd5%2FwRHBOn%2BTBN%2Fvx%2F2cBNvNkvzMOKR8kad5nkBGFzQVIhP1HDJe0aqu6imnWZ6k2UT6B4g9bDU6rp3HSGgeJmmY0COdMZqyySzK8vQHCTZei9LcjadenOuQxTFceNs1EAnTxgPpSYxoQgtSWRAuniezWTolwerOdm009i3YA9izEvBt%2F%2FwXi3edkqHh3rvIszkBjaAPT1VUNT206hJpcLcjZxpnyXwOdFGHM5FAOJ1Oq3BBIQ3rik%2BkoLyuZR435qR0yAWSYHez%2BIPSUunT%2B%2B5W1yVkn47HXbj7ejiS4KOxAsZgl8TZHkhZDGTY6J8tBzhVtUw0ppcMr%2FqQjaLY%2F5At4ke44osntd3sTKPE7%2BF2y92%2FOdOIjhPvXz2uMmi5alZSWkAvftU05nVtgTu4kY%2FL4tZPkKMon4yDiwvWpu24VTik7NMV7q7zcWvd%2BP7toS7frajwZgw9Rbbzn1dj5RCC7wXIo%2BUaO2PdTfWb4EX8JkU%2Ff%2Fy%2Fyj8%3D";

        generateSAMLResponse(samlReq);
    }

    public static String generateSAMLResponse(String samlRequest) throws Exception {
        // Instantiate the document to be signed
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        InputStream inputStream = XMLSigning.class.getClassLoader().getResourceAsStream("main/resources/saml-response.xml");

        Document doc = dbf.newDocumentBuilder().parse(inputStream);


        appendDataFromRequest(doc, readSAMLRequest(samlRequest));

        randomizeUser(doc);

//        printDom(doc);

        SAMLSigner.signAssertion(doc);


        DOMSource domDocSource = new DOMSource(doc);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(domDocSource, result);
//        System.out.println("\n After signature: \n" + writer.toString());
//        System.out.println("____________________");

        String compressedAndEncoded = compressAndEncodeString(writer.toString());
//        System.out.println(compressedAndEncoded);
//        System.out.println("____________________");

        String urlEncoded = URLEncoder.encode(compressedAndEncoded, "UTF-8");
//        System.out.println(urlEncoded);

        return urlEncoded;
    }

    private static void printDom(Document doc) throws TransformerException {
        DOMSource domDocSource = new DOMSource(doc);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(domDocSource, new StreamResult(System.out));
    }

    private static void randomizeUser(Document doc) {
        int randomNum = Math.abs(random.nextInt(100000));//we only randomize to beat the ratelimitter, we don't mind if we are not authenticate uniquely
        String userName = "user" + randomNum;
        String email = "user"+randomNum+"n@gmail.com";

        Node nameID = doc.getElementsByTagName("saml:NameID").item(0);
        nameID.setTextContent(email);

        NodeList attrValues = doc.getElementsByTagName("saml:AttributeValue");
        for (int i = 0; i < attrValues.getLength(); i++) {
            Node node = attrValues.item(i);
            Node parent = node.getParentNode();
            NamedNodeMap attrs = parent.getAttributes();
            Node nodeAttr = attrs.getNamedItem("Name");
            if( nodeAttr.getNodeValue().equals("name")){
                node.setTextContent(userName);
            }
            if( nodeAttr.getNodeValue().equals("email")){
                node.setTextContent(email);
            }
        }

    }

    private static void appendDataFromRequest(Document SAMLResponse, SAMLRequestData samlRequest) {
        Node response = SAMLResponse.getFirstChild();
        NamedNodeMap attrs = response.getAttributes();
        Node nodeAttr = attrs.getNamedItem("InResponseTo");
        nodeAttr.setTextContent(samlRequest.getId());

        nodeAttr = attrs.getNamedItem("Destination");
        nodeAttr.setTextContent(samlRequest.getAssertionConsumerServiceURL());

        Node assertionSubjectConfirmationData = SAMLResponse.getElementsByTagName("saml:SubjectConfirmationData").item(0);
        attrs = assertionSubjectConfirmationData.getAttributes();
        nodeAttr = attrs.getNamedItem("InResponseTo");
        nodeAttr.setTextContent(samlRequest.getId());

        nodeAttr = attrs.getNamedItem("Recipient");
        nodeAttr.setTextContent(samlRequest.getAssertionConsumerServiceURL());

//        Node assertionAudience = SAMLResponse.getElementsByTagName("saml:Audience").item(0);
//        assertionAudience.setNodeValue(samlRequest.getIssuer());
        NodeList list = SAMLResponse.getElementsByTagName("saml:AudienceRestriction").item(0).getChildNodes();
        for (int i = 0; i < list.getLength(); i++) {
            Node node = list.item(i);
            if ("saml:Audience".equals(node.getNodeName())) {
                node.setTextContent(samlRequest.getIssuer());
            }
        }
    }

    private static String compressAndEncodeString(String str) {
        DeflaterOutputStream def = null;
        String compressed = null;
        str=str.replaceAll("\\<\\?xml(.+?)\\?\\>", "").trim();
        try {
//            ByteArrayOutputStream out = new ByteArrayOutputStream();
//            // create deflater without header
//            def = new DeflaterOutputStream(out, new Deflater(Deflater.NO_COMPRESSION, true));
//            def.write(str.getBytes());
//            def.close();
//            compressed = Base64.getEncoder().encodeToString(out.toByteArray());
            compressed = Base64.getEncoder().encodeToString(str.getBytes());
        } catch(Exception e) {
            e.printStackTrace();
        }
        return compressed;
    }

    private static SAMLRequestData readSAMLRequest( String urlEncodedSamlReq) throws Exception {
        String xmlStr = decompressAndDecodeString(URLDecoder.decode(urlEncodedSamlReq, "UTF-8"));

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder;
        Document doc = null;
        try
        {
            builder = factory.newDocumentBuilder();
            doc = builder.parse( new InputSource( new StringReader( xmlStr )) );

        } catch (Exception e) {
            e.printStackTrace();
        }

        XPath xPath = XPathFactory.newInstance().newXPath();
        Element authnRequest = (Element)xPath.evaluate("/AuthnRequest",
                doc.getDocumentElement(), XPathConstants.NODE);
        SAMLRequestData data = new SAMLRequestData();
        data.setId(authnRequest.getAttribute("ID"));
        data.setIssueInstant(authnRequest.getAttribute("IssueInstant"));
        data.setAssertionConsumerServiceURL(authnRequest.getAttribute("AssertionConsumerServiceURL"));

        String issuer = doc.getElementsByTagName("saml:Issuer").item(0).getFirstChild().getNodeValue();
        data.setIssuer(issuer);
        return data;
    }

    private static String decompressAndDecodeString( String str) throws Exception{
        byte[] compressed = Base64.getDecoder().decode(str);
        return decompress(compressed, new byte[100000000]);
    }

    private static String decompress(byte[] compressedData, byte[] result) throws Exception {
        Inflater decompresser = new Inflater(true);
        decompresser.setInput(compressedData);
        int resultLength = decompresser.inflate(result);
        decompresser.end();

        return new String(result, 0, resultLength, "UTF-8");
    }

}