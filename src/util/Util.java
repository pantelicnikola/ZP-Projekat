/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import sun.security.x509.InhibitAnyPolicyExtension;
import x509.v3.GuiV3;


/**
 *
 * @author Nikola
 */
public class Util {
    
    private static final String KEY_STORE_NAME = "keystore";
    private static final String KEY_STORE_PASS = "asd";
    private static KeyStore keyStore;
    private static GuiV3 myAccess;
    private static String selectedKeyPair;
    private static PKCS10CertificationRequest currentRequest;
    
    public Util(GuiV3 access) {
        try {
            myAccess = access;
            keyStore.load(null, null);
            loadKeyStore();
        } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static void loadKeyStore() { // sinhronizacija izmedju lokalnog keyStore <-- fajla
        try {
            Security.addProvider(new BouncyCastleProvider());
            keyStore = KeyStore.getInstance("BKS", "BC");
            FileInputStream inputStream = new FileInputStream(KEY_STORE_NAME);
            keyStore.load(inputStream, KEY_STORE_PASS.toCharArray());
            inputStream.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException | NoSuchProviderException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static void storeKeyStore() { // sinhronizacija izmedju lokalnog keyStore --> fajla
        try {
            FileOutputStream outputStream = new FileOutputStream(KEY_STORE_NAME);
            keyStore.store(outputStream, KEY_STORE_PASS.toCharArray());
            outputStream.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public static void resetKeyStore() {
        File file = new File(KEY_STORE_NAME);
        file.delete();
    }
    
    public static int loadKeyPair(String keypair_name) {
        X509Certificate certificate = findCertificate(keyStore, keypair_name);
        if (certificate != null) {
            certificateToAccess(myAccess, certificate);
            selectedKeyPair = keypair_name;
            return 1;
        }
        return 0;
    }
    
    public static boolean saveKeyPair(String keypair_name) {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(myAccess.getPublicKeyECCurve());
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
            kpg.initialize(ecSpec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            X509Certificate certificate = accessToCertificate(myAccess, kp);
            Certificate certificates[] = {certificate};
            keyStore.setKeyEntry(keypair_name, kp.getPrivate(), KEY_STORE_PASS.toCharArray(), certificates);
            storeKeyStore();
        } catch (NoSuchAlgorithmException | KeyStoreException | InvalidAlgorithmParameterException | NoSuchProviderException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return true;
    }
    
    public static boolean removeKeypair(String keypair_name) {
        try {
            if (keyStore.containsAlias(keypair_name)) {
                keyStore.deleteEntry(keypair_name);
                storeKeyStore();
                return true;
            }
        } catch (KeyStoreException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public static boolean importKeypair(String keypair_name, String file, String password) {
        try {
            if (!keyStore.containsAlias(keypair_name)) {
                FileInputStream fileInputStream = new FileInputStream(file);
                KeyStore tmp = KeyStore.getInstance("pkcs12");
                tmp.load(fileInputStream, password.toCharArray());
                fileInputStream.close();
                
                X509Certificate certificate = findCertificate(tmp, KEY_STORE_NAME);
                Certificate certificates[] = {certificate};
                Key key = tmp.getKey(KEY_STORE_NAME, password.toCharArray());
            
                keyStore.setKeyEntry(keypair_name, key, KEY_STORE_PASS.toCharArray(), certificates);
                storeKeyStore();
                loadKeyStore();
                return true;
            }
            
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public static boolean exportKeypair(String keypair_name, String file, String password) {
        try {
            Certificate certificates[] = {findCertificate(keyStore, keypair_name)};
            if (certificates != null) {
                KeyStore tmp = KeyStore.getInstance("pkcs12");
                tmp.load(null, null);

                PrivateKey pk = (PrivateKey) keyStore.getKey(keypair_name, KEY_STORE_PASS.toCharArray());
                tmp.setKeyEntry(KEY_STORE_NAME, pk, password.toCharArray(), certificates);

                FileOutputStream outputStream = new FileOutputStream(file+".p12");
                tmp.store(outputStream, password.toCharArray());
                outputStream.close();
                return true;
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public static boolean signCertificate(String issuer, String algorithm) {
        try {
            X509Certificate issuerCertificate = findCertificate(keyStore, issuer);
            X509Certificate subjectCertificate = findCertificate(keyStore, selectedKeyPair);
            
            PrivateKey issuerPrivateKey = (PrivateKey) keyStore.getKey(issuer, KEY_STORE_PASS.toCharArray());
            PrivateKey subjectPrivateKey = (PrivateKey) keyStore.getKey(selectedKeyPair, KEY_STORE_PASS.toCharArray());
            
            KeyPair kp = new KeyPair(subjectCertificate.getPublicKey(), subjectPrivateKey);
            
            X500Name issuerDN = new X500Name (issuerCertificate.getSubjectDN().toString());
            BigInteger subjectSerialNumber = subjectCertificate.getSerialNumber();
            Date subjectNotBefore = subjectCertificate.getNotBefore();
            Date subejctNotAfter = subjectCertificate.getNotAfter();
            X500Name csrSubject = currentRequest.getCertificationRequestInfo().getSubject();
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
            X509v3CertificateBuilder cb = new X509v3CertificateBuilder(issuerDN, subjectSerialNumber, subjectNotBefore, subejctNotAfter, csrSubject, keyInfo);
            
            //extensions
            
            boolean issuerAlternativeNameCritical = false;
            boolean certificatePoliciesCritical = false;
            boolean inhibitAnyPolicyCritical = false;
            
            Set<String> criticals = subjectCertificate.getCriticalExtensionOIDs();
            for (String ext : criticals) {
                if (ext.equals(Extension.certificatePolicies.toString()))
                    certificatePoliciesCritical = true;
                else if (ext.equals(Extension.issuerAlternativeName.toString()))
                    issuerAlternativeNameCritical = true;
                else if (ext.equals(Extension.inhibitAnyPolicy.toString()))
                    inhibitAnyPolicyCritical = true;
            }
            
            Collection names = subjectCertificate.getIssuerAlternativeNames();
            int i = 0;
            GeneralName gn[] = new GeneralName[names.size()];
            for (Iterator it = names.iterator(); it.hasNext();) {
                List<Object> name = (List<Object>) it.next();
                gn[i] = new GeneralName(GeneralName.dNSName, name.toString());
                i++;
            }
            GeneralNames gns = new GeneralNames(gn);
            cb.addExtension(Extension.issuerAlternativeName, issuerAlternativeNameCritical, gns);
            
            byte[] extensionValue = subjectCertificate.getExtensionValue(Extension.inhibitAnyPolicy.toString());
            if (extensionValue != null) {
              Object obj = new ASN1InputStream(extensionValue).readObject();
              extensionValue = ((DEROctetString) obj).getOctets();
              obj = new ASN1InputStream(extensionValue).readObject();
              InhibitAnyPolicyExtension extension = new InhibitAnyPolicyExtension(new Integer(obj.toString()));
              cb.addExtension(X509Extensions.InhibitAnyPolicy, inhibitAnyPolicyCritical, extension.getExtensionValue());
            }
            
            

            //
            
            AlgorithmIdentifier saId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withECDSA"); // srediti
            AlgorithmIdentifier daId = new DefaultDigestAlgorithmIdentifierFinder().find(saId);
            
            AsymmetricKeyParameter akp = PrivateKeyFactory.createKey(issuerPrivateKey.getEncoded());
            ContentSigner cs = new BcECContentSignerBuilder(saId, daId).build(akp);
            
            X509CertificateHolder holder = cb.build(cs);
            org.bouncycastle.asn1.x509.Certificate structure = holder.toASN1Structure();
            
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            InputStream inputStream = new ByteArrayInputStream(structure.getEncoded());
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(inputStream);
            Certificate[] certificates = {certificate};
            inputStream.close(); 
            
            keyStore.deleteEntry(selectedKeyPair);
            keyStore.setKeyEntry(selectedKeyPair, subjectPrivateKey, KEY_STORE_PASS.toCharArray(), certificates);
            storeKeyStore();
            return true;
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException | OperatorCreationException | NoSuchProviderException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public static String getIssuer(String keypair_name) {
        return findCertificate(keyStore, keypair_name).getIssuerDN().toString();
    }
    
    public static List<String> getIssuers(String keypair_name) {
        List<String> list = Collections.list(getKeyStoreAliases());
        list.remove(keypair_name);
        return list;
    }
    
    public static String getIssuerPublicKeyAlgorithm(String keypair_name) {
        return findCertificate(keyStore, keypair_name).getSigAlgName();
    }
    
    public static boolean generateCSR(String keypair_name) {
        try {
            if (keyStore.containsAlias(keypair_name)) {
                X509Certificate certificate = findCertificate(keyStore, keypair_name);
                PublicKey pu = certificate.getPublicKey();
                PrivateKey pr = (PrivateKey) keyStore.getKey(keypair_name, KEY_STORE_PASS.toCharArray());
                String algorithm = "SHA1withECDSA"; // srediti
//                if (certificate.getSigAlgName().compareTo("EC")) {
//                    algorithm = certificate.getSigAlgName();
//                }
                currentRequest = new PKCS10CertificationRequest(algorithm, certificate.getSubjectX500Principal(), pu, null, pr);
                return true;
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchProviderException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public static Enumeration<String> getKeyStoreAliases() {
        try {
            return keyStore.aliases();
        } catch (KeyStoreException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return null; 
        }
    }
    
    public static X509Certificate accessToCertificate(GuiV3 access, KeyPair keyPair) {
        try {
            KeyFactory fact = KeyFactory.getInstance("ECDSA", "BC");
            PublicKey PU = fact.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
            PrivateKey PR = fact.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded()));
            
            X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
            X500Principal subjectPrincipal = new X500Principal(accesToDN(access));
            X500Principal issuerPrincipal = new X500Principal(accesToDN(access)); // srediti
            
            cg.setSerialNumber(new BigInteger(access.getSerialNumber()));
            cg.setNotBefore(access.getNotBefore());
            cg.setNotAfter(access.getNotAfter());
            cg.setSubjectDN(subjectPrincipal);
            cg.setIssuerDN(issuerPrincipal); // srediti
            cg.setPublicKey(PU);
            
            cg.setSignatureAlgorithm(access.getPublicKeySignatureAlgorithm());
            
//            if (access.getAnyPolicy()) {
//                final byte[] certificatePolicies = cert.getExtensionValue(X509Extension.certificatePolicies.getId());
//                ASN1Sequence asnoi = getASN1S;
//                
//                PolicyInformation pi = new PolicyInformation(asnoi);
//                PolicyInformation pis[] = {pi};
//                CertificatePolicies cp = new CertificatePolicies(pis);
//                cg.addExtension(Extension.issuerAlternativeName, access.isCritical(3), gns);
//            }
            
            if (access.getAlternativeName(6).length > 0) {
                GeneralName gn[] = new GeneralName[access.getAlternativeName(6).length];
                int i = 0;
                for (String name: access.getAlternativeName(6)) {
                    gn[i] = new GeneralName(GeneralName.dNSName, name);
                    i++;
                }
                GeneralNames gns = new GeneralNames(gn);
                cg.addExtension(Extension.issuerAlternativeName, access.isCritical(6), gns);
                
            }
            
            
            if (access.getInhibitAnyPolicy()) {
                InhibitAnyPolicyExtension iape = new InhibitAnyPolicyExtension(new Integer(access.getSkipCerts()));
                cg.addExtension(X509Extensions.InhibitAnyPolicy, access.isCritical(13), iape.getExtensionValue());
            }
            
            
            
            return cg.generateX509Certificate(PR, "BC");
        } catch (NoSuchProviderException | SecurityException | SignatureException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | IOException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public static X509Certificate findCertificate(KeyStore keyStore, String keypair_name) {
        try {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificateChain(keypair_name)[0];
            if (certificate == null) {
                certificate = (X509Certificate) keyStore.getCertificate(keypair_name);
            }
            return certificate;
        } catch (KeyStoreException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }        
    }
    
    public static void certificateToAccess(GuiV3 access, X509Certificate certificate) {
        try {
            Principal subjectDN = certificate.getSubjectDN();
            Principal issuerDN = certificate.getIssuerDN();
            
            access.setSubject(subjectDN.toString());
            access.setIssuer(issuerDN.toString());
            access.setVersion((certificate.getVersion())==3?2:1);
            access.setSerialNumber(certificate.getSerialNumber().toString());
            access.setNotBefore(certificate.getNotBefore());
            access.setNotAfter(certificate.getNotAfter());
            access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());

            Collection names = certificate.getIssuerAlternativeNames();
            if (names != null) {
                String alternativeNames = "";
                for (Iterator it = names.iterator(); it.hasNext();) {
                    List<Object> name = (List<Object>) it.next();
                    if (it.hasNext())
                        alternativeNames += name.get(1) + ",";
                    else
                        alternativeNames += name.get(1);
                }
                access.setAlternativeName(6, alternativeNames);  
            }
            
            byte[] extensionValue = certificate.getExtensionValue(Extension.inhibitAnyPolicy.toString());
            if (extensionValue != null) {
                Object obj = new ASN1InputStream(extensionValue).readObject();
                extensionValue = ((DEROctetString) obj).getOctets();
                obj = new ASN1InputStream(extensionValue).readObject();
                access.setInhibitAnyPolicy(true);
                access.setSkipCerts(obj.toString());
            }
            
            Set<String> criticals = certificate.getCriticalExtensionOIDs();
            if (criticals != null) {
                for (String ext : criticals) {
                    if (ext.equals(Extension.certificatePolicies.toString()))
                        access.setCritical(3, true);
                    else if (ext.equals(Extension.issuerAlternativeName.toString()))
                        access.setCritical(6, true);
                    else if (ext.equals(Extension.inhibitAnyPolicy.toString()))
                        access.setCritical(13, true);
                }
            }
            
        } catch (CertificateParsingException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    public static String accesToDN(GuiV3 access) {
        if (access != null)
            return  "C="+access.getSubjectCountry()+
                    ",ST="+access.getSubjectState()+
                    ",L="+access.getSubjectLocality()+
                    ",O="+access.getSubjectOrganization()+
                    ",OU="+access.getSubjectOrganizationUnit()+
                    ",CN="+access.getSubjectCommonName();
        return null;
    }
}
