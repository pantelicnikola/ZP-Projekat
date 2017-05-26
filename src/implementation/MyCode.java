/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package implementation;

import code.GuiException;
import java.io.File;
import java.util.Enumeration;
import java.util.List;
import util.Util;

/**
 *
 * @author Nikola
 */
public class MyCode extends x509.v3.CodeV3 {
    
    

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
        super(algorithm_conf, extensions_conf);
        new Util(access);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        Util.loadKeyStore();
        return Util.getKeyStoreAliases();
    }

    @Override
    public void resetLocalKeystore() {
        Util.resetKeyStore();
    }

    @Override
    public int loadKeypair(String string) {
        return Util.loadKeyPair(string);
    }

    @Override
    public boolean saveKeypair(String string) {
        return Util.saveKeyPair(string);
    }

    @Override
    public boolean removeKeypair(String string) {
        return Util.removeKeypair(string);
    }

    @Override
    public boolean importKeypair(String string, String string1, String string2) {
        return Util.importKeypair(string, string1, string2);
    }

    @Override
    public boolean exportKeypair(String string, String string1, String string2) {
        return Util.exportKeypair(string, string1, string2);
    }

    @Override
    public boolean signCertificate(String string, String string1) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean importCertificate(File file, String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean exportCertificate(File file, int i) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getIssuer(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public String getIssuerPublicKeyAlgorithm(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int getRSAKeyLength(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public List<String> getIssuers(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public boolean generateCSR(String string) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
