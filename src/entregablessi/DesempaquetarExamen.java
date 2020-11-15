package entregablessi;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import paquete.Paquete;
import paquete.PaqueteDAO;

public class DesempaquetarExamen {

    public static void main(String[] args){
        /*if (args.length != 2) {
            System.exit(1);
        }*/
        
        String dir = "/tmp/"+args[0];
        Paquete paquete = PaqueteDAO.leerPaquete(dir);

        System.out.println("Desempaquetado del examen.");

        Security.addProvider(new BouncyCastleProvider());

        Cipher cifrador = null;
        try {
            cifrador = Cipher.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error: NO existe tal algoritmo");
        } catch (NoSuchProviderException ex) {
            System.err.println("Error. No existe tal proveedor");
        } catch (NoSuchPaddingException ex) {
            System.err.println("Error: No existe tal relleno.");
        }

        PublicKey publicaAlumno = recuperarClavePublica(args[1]);
        try {
            cifrador.init(Cipher.DECRYPT_MODE, publicaAlumno);
        } catch (InvalidKeyException ex) {
            System.err.println("Error: CLave privada no valida.");
        }
        byte[] resumen1 = null;
        try {
            resumen1 = cifrador.doFinal(paquete.getContenidoBloque("FIRMA"));
        } catch (IllegalBlockSizeException ex) {
            System.err.println("Error: Tamano de bloque incorrecto en resumen1");
        } catch (BadPaddingException ex) {
            System.err.println("Error: Relleno incorrecto en resumen1");
        }

        byte[] examenCifrado = paquete.getContenidoBloque("EXAMEN_CIFRADO");
        byte[] claveSecretaCifrada = paquete.getContenidoBloque("CLAVE_SECRETA");

        MessageDigest messageDigest = null;
        try {

            messageDigest = MessageDigest.getInstance("SHA");

        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error:NO existe tal algoritmo en digest.");
        }

        messageDigest.update(examenCifrado);
        messageDigest.update(claveSecretaCifrada);

        byte[] resumen = messageDigest.digest();
        System.out.println("Comprobamos que el examen y la clave secreta enviado por el alumno es igual al enviado por la autoridad.");
        if (!Arrays.equals(resumen1, resumen)) {
            System.exit(1);
            System.out.println("Error en la comprobacion de examen y clave secreta. No coinciden.");
        }
        String s = new String(paquete.getContenidoBloque("FECHA"));
        System.out.println("Sellado en "+s);
        byte[] bytes_sellado = paquete.getContenidoBloque("SELLADO");
        cifrador = null;
        PublicKey autoridadPublica = recuperarClavePublica(args[3]);
        try {
            cifrador = Cipher.getInstance("RSA", "BC");
            cifrador.init(Cipher.DECRYPT_MODE, autoridadPublica);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: No existe tal algoritmo de encriptacion");
        } catch (InvalidKeyException e) {
            System.err.println("Error: No existe tal clave o es invalida.");
        } catch (NoSuchPaddingException e) {
            System.err.println("Error: No existe tal relleno.");
        } catch (NoSuchProviderException e) {
            System.err.println("Error: No existe tal provider.");
        }
        byte[] sellado1 = null;
        try {
            sellado1 = cifrador.doFinal(bytes_sellado);
        } catch (IllegalBlockSizeException ex) {
            System.err.println("Error: Tamano de bloque incorrecto en resumen1");
        } catch (BadPaddingException ex) {
            System.err.println("Error: Relleno incorrecto en resumen1");
        }

        messageDigest = null;
        try {

            messageDigest = MessageDigest.getInstance("SHA");

        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error:NO existe tal algoritmo en digest.");
        }
        messageDigest.update(paquete.getContenidoBloque("FECHA"));
        messageDigest.update(paquete.getContenidoBloque("EXAMEN_CIFRADO"));
        messageDigest.update(paquete.getContenidoBloque("CLAVE_SECRETA"));
        messageDigest.update(paquete.getContenidoBloque("FIRMA"));

        byte[] sellado2 = messageDigest.digest();

        System.out.println("Comprobamos que el sellado es correcto.");
        if (!Arrays.equals(sellado1, sellado2)) {
            System.out.println("No son guales");
        }

        //Ya que todo esta correcto, procedemos a mostrar el examen.
        PrivateKey privadaProfesor = recuperarClavePrivada(args[2]);
        try {
            cifrador = Cipher.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error: NO existe tal algoritmo");
        } catch (NoSuchProviderException ex) {
            System.err.println("Error. No existe tal proveedor");
        } catch (NoSuchPaddingException ex) {
            System.err.println("Error: No existe tal relleno.");
        }
        try {
            cifrador.init(Cipher.DECRYPT_MODE, privadaProfesor);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        }

        byte[] claveDES = null;

        try {
            claveDES = cifrador.doFinal(paquete.getContenidoBloque("CLAVE_SECRETA"));
        } catch (IllegalBlockSizeException ex) {
            System.err.println("Error: Tamano de bloque incorrecto en resumen1");
        } catch (BadPaddingException ex) {
            System.err.println("Error: Relleno incorrecto en resumen1");
        }

        SecretKeyFactory factoryDES = null;
        try {
            factoryDES = SecretKeyFactory.getInstance("DES");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        }
        SecretKey clavePrivada = null;
        try {
            clavePrivada = factoryDES.generateSecret(new DESKeySpec(claveDES));
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        }

        FileOutputStream out = null;

        try {
            out = new FileOutputStream("examen_descifrado.txt");
        } catch (FileNotFoundException ex) {

        }
        byte[] bufferExamen = null;
        try {
            cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cifrador.init(Cipher.DECRYPT_MODE,clavePrivada);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            bufferExamen = cifrador.doFinal(paquete.getContenidoBloque("EXAMEN_CIFRADO"));
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        }

        try {
            out.write(bufferExamen);
            out.close();
        } catch (IOException ex) {
            Logger.getLogger(DesempaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("Examen descrifrado en la carpeta Claves con nombre 'examen_descifrado.txt'");

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

    private static PublicKey recuperarClavePublica(String nombre) {
        File ficheroClavePublica = new File(nombre);
        int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
        byte[] bufferPublica = new byte[tamanoFicheroClavePublica];
        FileInputStream in = null;
        KeyFactory KeyFactoryRSA = null;
        try {
            KeyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error: No existe tal algoritmo en KeyFactory");
        } catch (NoSuchProviderException ex) {
            System.err.println("Error: No existe tal proveedor");
        }

        try {
            in = new FileInputStream(ficheroClavePublica);
        } catch (FileNotFoundException ex) {
            System.err.println("Error: Error en la lectura del fichero de clave publica.");
        }
        try {
            in.read(bufferPublica, 0, tamanoFicheroClavePublica);
            in.close();
        } catch (IOException e) {
            System.err.println("Error: Error en el cierre o lectura del fichero de clave publica");
        }

        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPublica);
        PublicKey clavePublica = null;
        try {
            clavePublica = KeyFactoryRSA.generatePublic(clavePublicaSpec);
        } catch (InvalidKeySpecException ex) {
            System.err.println("Error: Clave publica invalida");
        }

        return clavePublica;
    }
}
