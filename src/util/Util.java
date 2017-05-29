/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
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
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Iterator;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import static org.bouncycastle.asn1.x509.X509Extensions.InhibitAnyPolicy;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import sun.security.x509.InhibitAnyPolicyExtension;
import sun.security.x509.X509CertImpl;
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

    
    
    
    public Util(GuiV3 access) {
        myAccess = access;
        loadKeyStore();
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
                
                X509Certificate certificate = findCertificate(tmp, keypair_name);
                Certificate certificates[] = {certificate};
                Key key = tmp.getKey(keypair_name, password.toCharArray());
            
                keyStore.setKeyEntry(keypair_name, key, KEY_STORE_PASS.toCharArray(), certificates);
                storeKeyStore();
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
            KeyStore ks = KeyStore.getInstance("pkcs12");
            ks.load(null, null);
            
            //PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(keypair_name, new KeyStore.PasswordProtection(KEY_STORE_PASS.toCharArray()));
            Certificate certificates[] = {findCertificate(keyStore, keypair_name)};
            PrivateKey pk = (PrivateKey) keyStore.getKey(keypair_name, password.toCharArray());
            ks.setKeyEntry(KEY_STORE_NAME, pk, password.toCharArray(), certificates);
           
            FileOutputStream outputStream = new FileOutputStream(file+".p12");
            ks.store(outputStream, password.toCharArray());
            outputStream.close();
            
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }
    
    public static boolean signCertificate(String issuer, String algorithm) {
        try {
            KeyStore.Entry issuerEntry = keyStore.getEntry(issuer, new KeyStore.PasswordProtection(KEY_STORE_PASS.toCharArray()));
            KeyStore.Entry subjectEntry = keyStore.getEntry(selectedKeyPair, new KeyStore.PasswordProtection(KEY_STORE_PASS.toCharArray()));
            
            X509Certificate issuerCertificate = (X509Certificate) keyStore.getCertificate(issuer);
            X509Certificate subjeCertificate = (X509Certificate) keyStore.getCertificate(selectedKeyPair);
            
            X509CertImpl impl = new X509CertImpl(subjeCertificate.getEncoded());
            Collection sANsCollection = impl.getSubjectAlternativeNames();
            String sANs[];
            if (sANsCollection != null) {
                sANs = new String[sANsCollection.size()];
                int i = 0;
                for (Iterator iterator = sANsCollection.iterator(); iterator.hasNext();) {
                    
                }
            }            
            
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException | CertificateException ex) {
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
            ECPublicKey PU = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey PR = (ECPrivateKey) keyPair.getPrivate();
            X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
            X500Principal subjectPrincipal = new X500Principal(accesToDN(access));
            Principal issuerDn = null;
            
            cg.setSerialNumber(new BigInteger(access.getSerialNumber()));
            cg.setNotBefore(access.getNotBefore());
            cg.setNotAfter(access.getNotAfter());
            cg.setSubjectDN(subjectPrincipal);
            cg.setIssuerDN(new X500Principal("")); // srediti
            cg.setPublicKey(PU);
            
            cg.setSignatureAlgorithm(access.getPublicKeySignatureAlgorithm());
            
            //if (access.isCritical(2))
            for (int i = 0 ; i<15 ; i++ ) {
                if (access.isCritical(i)) System.out.println(i);
            }
            
            if (access.getAnyPolicy()) {
                GeneralName gn[] = new GeneralName[access.getAlternativeName(3).length];
                int i = 0;
                for (String name: access.getAlternativeName(3)) {
                    gn[i] = new GeneralName(GeneralName.dNSName, name);
                    i++;
                }
                GeneralNames gns = new GeneralNames(gn);
                cg.addExtension(Extension.issuerAlternativeName, access.isCritical(3), gns);
            }
            
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
                GeneralName gn[] = new GeneralName[access.getAlternativeName(13).length];
                int i = 0;
                for (String name: access.getAlternativeName(13)) {
                    gn[i] = new GeneralName(GeneralName.dNSName, name);
                    i++;
                }
                GeneralNames gns = new GeneralNames(gn);
                cg.addExtension(Extension.issuerAlternativeName, access.isCritical(13), gns);
            } // mozda fali ELSE
            
            
            
            return cg.generateX509Certificate(PR, "BC");
        } catch (NoSuchProviderException | SecurityException | SignatureException | InvalidKeyException ex) {
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
        Principal subjectDN = certificate.getSubjectDN();
        Principal issuerDN = certificate.getIssuerDN();
        
        access.setSubject(subjectDN.toString());
        access.setIssuer(subjectDN.toString()); // ispraviti
        
        access.setVersion((certificate.getVersion())==3?2:1);
        access.setSerialNumber(certificate.getSerialNumber().toString());
        access.setNotBefore(certificate.getNotBefore());
        access.setNotAfter(certificate.getNotAfter());
        access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());
        
        
    }
    
    public static String accesToDN(GuiV3 access) {
        if (access != null)
            return  " C="+access.getSubjectCountry()+
                    ",ST="+access.getSubjectState()+
                    ",L="+access.getSubjectLocality()+
                    ",O="+access.getSubjectOrganization()+
                    ",OU="+access.getSubjectOrganizationUnit()+
                    ",CN="+access.getSubjectCommonName();
        return null;
        
    }
    
}
