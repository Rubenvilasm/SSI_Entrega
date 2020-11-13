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
import java.util.Base64;
import java.util.Calendar;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import paquete.Paquete;
import paquete.PaqueteDAO;

public class DesempaquetarExamen {

    public static void main(String[] args) {
        /*if (args.length != 2) {
            System.exit(1);
        }*/
        Paquete paquete = PaqueteDAO.leerPaquete("/tmp/paquete1.bin");
        List<String> nombresBloque = paquete.getNombresBloque();
        System.out.println(nombresBloque.toString());

        System.out.println("Iniciamos el desempaquetado por DES del fichero");

        Security.addProvider(new BouncyCastleProvider());
        paquete.getContenidoBloque(nombresBloque.get(1));

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
        
        PublicKey publicaAlumno = recuperarClavePublica(args[0]);
        EmpaquetarExamen.mostrarPaquete(paquete);
        try {
            cifrador.init(Cipher.DECRYPT_MODE,publicaAlumno);
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
        
        if(!Arrays.equals(resumen1, resumen)){
            System.exit(1);
        }
        
        
        
        
        
        cifrador = null;
        try {
            cifrador = Cipher.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error: NO existe tal algoritmo");
        } catch (NoSuchProviderException ex) {
            System.err.println("Error. No existe tal proveedor");
        } catch (NoSuchPaddingException ex) {
            System.err.println("Error: No existe tal relleno.");
        }
        
        PrivateKey privadaProfesor = recuperarClavePrivada(args[1]);
        EmpaquetarExamen.mostrarPaquete(paquete);
        try {
            cifrador.init(Cipher.DECRYPT_MODE,privadaProfesor);
        } catch (InvalidKeyException ex) {
            System.err.println("Error: CLave privada no valida.");
        }
        byte[] bufferKS = null;
        try {
            bufferKS = cifrador.doFinal(paquete.getContenidoBloque("CLAVE_SECRETA"));
        } catch (IllegalBlockSizeException ex) {
            System.err.println("Error: Tamano de bloque incorrecto en resumen1");
        } catch (BadPaddingException ex) {
            System.err.println("Error: Relleno incorrecto en resumen1");
        }
        
        SecretKeyFactory secretKeyFactoryDES;
        SecretKey claveSecreta = null;
        try {
            secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
            DESKeySpec DESspec;
            DESspec = new DESKeySpec(bufferKS);
             claveSecreta = secretKeyFactoryDES.generateSecret(DESspec);
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error: No existe tal algoritmo.");
        } catch (InvalidKeyException ex) {
            System.err.println("Error: Clave DESKey invalida.");
        } catch (InvalidKeySpecException ex) {
            System.err.println("Error: clave KeySpec invalida.");
        }
        
        
        try {
            cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error: No existe tal algoritmo");
        } catch (NoSuchPaddingException ex) {
            System.err.println("Error: No existe tal relleno.");
        }
        try {
            cifrador.init(Cipher.DECRYPT_MODE, claveSecreta);
        } catch (InvalidKeyException ex) {
            System.err.println("Error: claveSecreta invalida.");
        }
        FileOutputStream out = null;
        try {
             out = new FileOutputStream("examen.descifrado");
        } catch (FileNotFoundException ex) {
            System.err.println("Error: NO existe tal archivo");
        }
        byte[] bufferExamen = null;
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
            System.err.println("Error: IO exception");
        }
        
        
        
        //Calendar date = paquete.getContenidoBloque("FECHA");
      //  System.out.println(date.length);
        String s = new String(paquete.getContenidoBloque("FECHA"));
        System.out.println(s);
    
    }

    private static PrivateKey recuperarClavePrivada(String nombre) {
        KeyFactory keyFactoryRSA = null;
        try {
            keyFactoryRSA = KeyFactory.getInstance("RSA","BC");
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
