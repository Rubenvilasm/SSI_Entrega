package practica1;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import paquete.Paquete;
import paquete.PaqueteDAO;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author ruben
 */
public class SellarExamen {

    public static void main(String args[]){
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("Sellando el paquete: "+args[0]);
        String dir = "/tmp/"+args[0];
        
        Paquete paquete = PaqueteDAO.leerPaquete(dir);
        Calendar cal = Calendar.getInstance();
        System.out.println(cal.getTime().toString());
        byte[] buffer_fecha = cal.getTime().toString().getBytes();
        System.out.println("Añadiendo Fecha al paquete...");
        paquete.anadirBloque("FECHA", buffer_fecha);

        
        
        byte[] buffer_firma = paquete.getContenidoBloque("FIRMA");
        byte[] buffer_examen = paquete.getContenidoBloque("EXAMEN_CIFRADO");
        byte[] buffer_clave = paquete.getContenidoBloque("CLAVE_SECRETA");

        MessageDigest messageDigest = null;
        try {

            messageDigest = MessageDigest.getInstance("SHA");

        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error:NO existe tal algoritmo en digest.");
        }
        messageDigest.update(paquete.getContenidoBloque("FECHA"));
        messageDigest.update(paquete.getContenidoBloque("EXAMEN_CIFRADO"));
        messageDigest.update(paquete.getContenidoBloque("CLAVE_SECRETA"));
        messageDigest.update(paquete.getContenidoBloque("FIRMA"));

        byte[] sello = messageDigest.digest();

        Cipher cifrador = null;
        byte[] bufferSellado = null;
       
        PrivateKey privadaAutoridad = recuperarClavePrivada(args[1]);
        try {
            cifrador = Cipher.getInstance("RSA", "BC");
            cifrador.init(Cipher.ENCRYPT_MODE, privadaAutoridad);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: No existe tal algoritmo de encriptacion");
        } catch (InvalidKeyException e) {
            System.err.println("Error: No existe tal clave o es invalida.");
        } catch (NoSuchPaddingException e) {
            System.err.println("Error: No existe tal relleno.");
        } catch (NoSuchProviderException e) {
            System.err.println("Error: No existe tal provider.");
        }
        
        try {
            bufferSellado = cifrador.doFinal(sello);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(SellarExamen.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(SellarExamen.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        paquete.anadirBloque("SELLADO", bufferSellado);
        PaqueteDAO.escribirPaquete(dir, paquete);
        
        System.out.println("Paquete sellado correctamente.");
        

    }

    private static PrivateKey recuperarClavePrivada(String nombre) {
        KeyFactory keyFactoryRSA = null;
        try {
            keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error: No existe tal algoritmo.");
        } catch (NoSuchProviderException ex) {
            System.err.println("Error: No existe tal provider.");
        }
        File ficheroClavePrivada = new File(nombre);
        int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
        byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
        FileInputStream in = null;
        try {
            in = new FileInputStream(ficheroClavePrivada);
        } catch (FileNotFoundException ex) {
            System.err.println("Error: No se encuentra el fichero.");
        }
        try {
            in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
            in.close();
        } catch (IOException ex) {
            System.err.println("Error: Error de entrada/salida");
        }

        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = null;
        try {
            clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
        } catch (InvalidKeySpecException ex) {
            System.err.println("Error: Clave invalida");
        }

        return clavePrivada;
    }

}
