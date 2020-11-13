package entregablessi;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Calendar;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.*;
import javax.crypto.interfaces.*;

import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import paquete.Paquete;
import paquete.PaqueteDAO;

public class EmpaquetarExamen {

    public static final void main(String[] args) {
        if (args.length != 3) {
            System.exit(1);
        }

        //CLave DES
        System.out.println("1.Generamos la clave DES");
        KeyGenerator generadorDES;
        SecretKey clave = null;
        Security.addProvider(new BouncyCastleProvider());

        try {
            generadorDES = KeyGenerator.getInstance("DES");
            generadorDES.init(56);
            clave = generadorDES.generateKey();
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error generando la instancia DES");
        }

        Cipher cifrador = null;
        try {
            cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error, no existe ese algoritmo");
        } catch (NoSuchPaddingException ex) {
            System.err.println("Error, no existe ese relleno.");
        }

        try {
            cifrador.init(Cipher.ENCRYPT_MODE, clave);
        } catch (InvalidKeyException ex) {
            System.err.println("Error en el init de cifrado.");
        }

        /*
        *Creamos el fichero cifrado con DES, que será el que se incluya en el paquete
         */
        byte[] buffer = new byte[1000];
        byte[] bufferCifrado = null;
        FileInputStream in = null;

        byte[] buffer1 = null;
        try {
            buffer1 = Files.readAllBytes(Paths.get(args[0]));
        } catch (IOException ex) {
            Logger.getLogger(EmpaquetarExamen.class.getName()).log(Level.SEVERE, null, ex);
        }

        try {
            bufferCifrado = cifrador.doFinal(buffer1);
        } catch (IllegalBlockSizeException e) {
            System.err.println("Error: Tamaño del bloque incorrecto.");
        } catch (BadPaddingException ex) {
            System.err.println("Error: Relleno incorrecto");
        }

        PublicKey publicaProfesor = recuperarClavePublica(args[1]);
        byte[] bufferPlano = clave.getEncoded();

        try {
            cifrador = Cipher.getInstance("RSA", "BC");
            cifrador.init(Cipher.ENCRYPT_MODE, publicaProfesor);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: No existe tal algoritmo de encriptacion");
        } catch (InvalidKeyException e) {
            System.err.println("Error: No existe tal clave o es invalida.");
        } catch (NoSuchPaddingException e) {
            System.err.println("Error: No existe tal relleno.");
        } catch (NoSuchProviderException e) {
            System.err.println("Error: No existe tal provider.");
        }
        byte[] bufferCifradoKS = null;
        try {
            bufferCifradoKS = cifrador.doFinal(bufferPlano);
        } catch (IllegalBlockSizeException ex) {
            System.err.println("Error: Tamano de bloque no soportado");
        } catch (BadPaddingException ex) {
            System.err.println("Error: Error en el relleno.");
        }

        System.out.println("BuferCifrado");
        mostrarBytes(bufferCifradoKS); //A realizar hash y añadir al paquete CLAVE SECRETA
        Paquete p = new Paquete();
        p.anadirBloque("Examen cifrado", bufferCifrado);
        p.anadirBloque("Clave secreta", bufferCifradoKS);
        PaqueteDAO.escribirPaquete("/tmp/paquete1.bin", p);
        System.out.println("\nPaquete guardado");

        /*HASHING
            ¿Como uno el examen pasado por des y la KS pasada por RSA?
            r: Haciendo update de las dos secuencialmente.
         */
        MessageDigest messageDigest = null;
        try {

            messageDigest = MessageDigest.getInstance("SHA");

        } catch (NoSuchAlgorithmException ex) {
            System.err.println("Error:NO existe tal algoritmo en digest.");
        }

        messageDigest.update(bufferCifrado);
        messageDigest.update(bufferCifradoKS);

        byte[] resumen = messageDigest.digest();

        System.out.println("Resumen:");
        mostrarBytes(resumen);

        /*CIfrado del hash con KR alumno*/
        PrivateKey privadaAlumno = recuperarClavePrivada(args[2]);

        try {
            cifrador.init(Cipher.ENCRYPT_MODE, privadaAlumno);
        } catch (InvalidKeyException ex) {
            System.err.println("Error: Clave privada del alumno no valida.");
        }
        byte[] cifradoAlumno = null;
        try {
            cifradoAlumno = cifrador.doFinal(resumen);
        } catch (IllegalBlockSizeException ex) {
            System.err.println("Error: Tamano de bloque incorrecto.");
        } catch (BadPaddingException ex) {
            System.err.println("Error: El relleno es incorrecto.");
        }
        /*Añadimos el bloque firma que acabamos de crear con messageDigest al paquete*/
        p.anadirBloque("FIRMA", cifradoAlumno);
        PaqueteDAO.escribirPaquete("/tmp/paquete1.bin", p);

        mostrarPaquete(p);

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

    public static byte[] leerLinea(java.io.InputStream in) throws IOException {
        byte[] buffer1 = new byte[1000];
        int i = 0;
        byte c;
        c = (byte) in.read();
        while ((c != '\n') && (i < 1000)) {
            buffer1[i] = c;
            c = (byte) in.read();
            i++;
        }

        byte[] buffer2 = new byte[i];
        for (int j = 0; j < i; j++) {
            buffer2[j] = buffer1[j];
        }
        return (buffer2);
    }

    public static void mostrarBytes(byte[] buffer) {
        System.out.write(buffer, 0, buffer.length);
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

    public static void mostrarPaquete(Paquete p) {

        List<String> nombresBloque = p.getNombresBloque();
        System.out.println("\n");
        for (String actual : nombresBloque) {
            System.out.println(actual);
            mostrarBytes(p.getContenidoBloque(actual));
            System.out.println("\n\n\n");
        }
    }
}
