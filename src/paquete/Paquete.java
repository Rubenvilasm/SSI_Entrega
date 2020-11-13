package paquete;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author ribadas
 */
public class Paquete {

    private Map<String, Bloque> bloques;

    public Paquete() {
        this.bloques = new HashMap<>();
    }

    public byte[] getContenidoBloque(String nombreBloque) {
        Bloque bloque = this.bloques.get(nombreBloque);
        if (bloque != null) {
            return bloque.contenido;
        } else {
            return null;
        }
    }

    public void anadirBloque(String nombre, byte[] contenido) {
        if (this.bloques == null) {
            this.bloques = new HashMap<>();
        }
        String nombreNormalizado = normalizarNombre(nombre);
        this.bloques.put(nombreNormalizado, new Bloque(nombreNormalizado, contenido));
    }

    public void actualizarBloque(String nombre, byte[] contenido) {
        if (this.bloques != null) {
            if (this.bloques.containsKey(nombre)) {
                Bloque bloque = new Bloque(nombre, contenido);
                this.bloques.replace(nombre, bloque);
            } else {
                this.anadirBloque(nombre, contenido);
            }
        }
    }

    public void eliminarBloque(String nombre) {
        if (this.bloques != null) {
            this.bloques.remove(nombre);
        }
    }

    public List<String> getNombresBloque() {
        List<String> result = new ArrayList<String>(this.bloques.keySet());

        Collections.sort(result);
        return result;
    }

    private String normalizarNombre(String nombreBloque) {
        String result = nombreBloque.trim().replaceAll(" ", "_").toUpperCase();
        return result;
    }

    public static class Bloque {

        public String nombre;
        public byte[] contenido;

        public Bloque(String nombre, byte[] contenido) {
            this.nombre = nombre;
            this.contenido = contenido;
        }

    }
}
