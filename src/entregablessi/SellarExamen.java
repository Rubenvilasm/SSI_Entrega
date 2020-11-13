package entregablessi;

import java.util.Calendar;
import java.util.Date;
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
    public static void main (String args[]){
        Paquete paquete = PaqueteDAO.leerPaquete("/tmp/paquete1.bin");
        
        Calendar cal = Calendar.getInstance();
        System.out.println(cal.getTime().toString());
        
        paquete.anadirBloque("FECHA", cal.getTime().toString().getBytes());
        
        PaqueteDAO.escribirPaquete("/tmp/paquete1.bin", paquete);
        
        EmpaquetarExamen.mostrarPaquete(paquete);
        
        
        
        
        
    }
    
    
}
