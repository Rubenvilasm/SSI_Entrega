package entregablessi;

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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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

    public static void main(String args[]) {
        Paquete paquete = PaqueteDAO.leerPaquete("/tmp/paquete1.bin");

        Calendar cal = Calendar.getInstance();
        System.out.println(cal.getTime().toString());
        byte[] buffer_fecha = cal.getTime().toString().getBytes();
        paquete.anadirBloque("FECHA", fecha);

        PaqueteDAO.escribirPaquete("/tmp/paquete1.bin", paquete);

        EmpaquetarExamen.mostrarPaquete(paquete);

        byte[] buffer_firma = paquete.getContenidoBloque("FIRMA");
        byte[] buffer_examen = paquete.getContenidoBloque("EXAMEN_CIFRADO");
        byte[] buffer_clave = paquete.getContenidoBloque("CLAVE_SECRETA");

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
        MessageDigest messageDigest = null;
        try {
            bufferSellado = cifrador.doFinal(buffer_examen);
            bufferSellado = cifrador.doFinal(buffer_clave);
            bufferSellado = cifrador.doFinal(buffer_fecha);
            bufferSellado = cifrador.doFinal(buffer_firma);

        } catch (IllegalBlockSizeException ex) {
            System.err.println("Error: Tamano de bloque no soportado");
        } catch (BadPaddingException ex) {
            System.err.println("Error: Error en el relleno.");
        }
        
        

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
