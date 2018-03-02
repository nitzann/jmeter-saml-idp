package main.java.com.ibm.appid.saml.perf;

public class SAMLRequestData {
    private String id;
    private String IssueInstant;
    private String AssertionConsumerServiceURL;
    private String issuer;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getIssueInstant() {
        return IssueInstant;
    }

    public void setIssueInstant(String issueInstant) {
        IssueInstant = issueInstant;
    }

    public String getAssertionConsumerServiceURL() {
        return AssertionConsumerServiceURL;
    }

    public void setAssertionConsumerServiceURL(String assertionConsumerServiceURL) {
        AssertionConsumerServiceURL = assertionConsumerServiceURL;
    }
}