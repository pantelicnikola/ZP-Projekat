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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import x509.v3.GuiV3;

/**
 *
 * @author Nikola
 */
public class Util {

    //private static KeyStoreUtil keyStore = null;
    private static final String KEY_STORE_NAME = "keystore";
    private static final String KEY_STORE_PASS = "asd";
    private static KeyStore keyStore = null;
    private static boolean isInitialized = false;
    
    public Util() {
        isInitialized = true;
    }

//    public static KeyStoreUtil getKeyStore() {
//        if (keyStore == null) {
//            return new KeyStoreUtil();
//        } else {
//            return keyStore;
//        }        
//    }
    
    public static void loadKeyStore() {
        if (isInitialized)
            try {
                keyStore = null;
                FileInputStream inputStream = new FileInputStream(KEY_STORE_NAME);
                keyStore.load(inputStream, KEY_STORE_PASS.toCharArray());
                inputStream.close();
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
                Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            }
    }
    
    public static void storeKeyStore() {
        if(isInitialized)
            try {
                FileOutputStream outputStream = new FileOutputStream(KEY_STORE_NAME);
                keyStore.store(outputStream, KEY_STORE_PASS.toCharArray());
            } catch (FileNotFoundException ex) {
                Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
                Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
            }
    }
    
    public static Enumeration<String> getKeyStoreAliases() {
        if(isInitialized)
            try {
                return keyStore.aliases();
            } catch (KeyStoreException ex) {
                Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
                return null; 
           }
        else return null;
    }
    
    public static void resetKeyStore() {
        if (isInitialized) {
            File file = new File(KEY_STORE_NAME);
            file.delete();
        } 
    }
    
    public static int loadKeyPair(String string) {
        try {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificateChain(string)[0];
            if (certificate == null) {
                certificate = (X509Certificate) keyStore.getCertificate(string);
            }
                
        } catch (KeyStoreException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
        return 0;
    }
    
    
    public void accessToCertificate(GuiV3 access, X509Certificate certificate) {
        
    }
    
    public void certificateToAccess(GuiV3 access, X509Certificate certificate) {
        Principal subjectDN = certificate.getSubjectDN();
        Principal issuerDN = certificate.getIssuerDN();
        
        try {
            LdapName ldapName = new LdapName(subjectDN.toString());
            int i = 1;
            for (Rdn rdn : ldapName.getRdns()) {
                switch(i) {
                    case 6:
                        access.setSubjectCommonName((String) rdn.getValue());
                        break;
                    case 5:
                        access.setSubjectOrganizationUnit((String) rdn.getValue());
                        break;
                    case 4:
                        access.setSubjectOrganization((String) rdn.getValue());
                        break;
                    case 3:
                        access.setSubjectLocality((String) rdn.getValue());
                        break;
                    case 2:
                        access.setSubjectState((String) rdn.getValue());
                        break;
                    case 1:
                        access.setSubjectCountry((String) rdn.getValue());
                        break;
                }
                i++;
            }
            access.setVersion((certificate.getVersion())==3?2:1);
            access.setSerialNumber(certificate.getSerialNumber().toString());
            access.setNotBefore(certificate.getNotBefore());
            access.setNotAfter(certificate.getNotAfter());
            
            
        } catch (InvalidNameException ex) {
            Logger.getLogger(Util.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
}
