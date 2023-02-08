/**
 * A packet analyzer that takes a binary file as input and 
 * displays the header information
 * 
 * @author: Snehil Sharma (ss7696)
 * 
 */


import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Scanner;


public class pktanalyzer{

    //for use across functions
    public boolean ip_options = false;

    public int ip_header_length = 0;

    /**
     * readds the binary file and returns a byte array
     * @param pkt_name binary file  
     * @return  byte array
     */
    public byte[] read_packet(String pkt_name){

        File the_pkt = new File(pkt_name);

        byte[] data = new byte[(int) the_pkt.length()];
        
        try {

            DataInputStream reader = new DataInputStream(new FileInputStream(the_pkt));

            reader.read(data);

            reader.close();

        } catch (FileNotFoundException e) {
            
            e.printStackTrace();
        }

        catch (IOException e){

            System.out.println(e);
        }

        return data;

    }

    //takes two bytes and combunes them
    public byte combine_bytes(byte b1, byte b2){

        byte combined_byte =  (byte) ( ((Byte.toUnsignedInt(b1) ) << 8 ) | ( Byte.toUnsignedInt(b2) ) );

        return combined_byte;
    }

    //takes a byte  and splits it into 4 bit halves 
    public byte[] split_the_byte(byte b){

        byte[] split_bytes = new byte[2];

        split_bytes[0] = (byte) (((int) b) >> 4);
        split_bytes[1] = (byte) (((int) b) & 0x0F);

        return split_bytes;
    }

    //returns the dscp value in hex
    public String[] get_dscp_values(byte b){

        byte six_bits = (byte) ( ((int) b) >> 2);
        byte b1 = (byte) (((int)six_bits) & 0x07);
        byte b0 = (byte) ((((int)six_bits) & 0x38) >> 3);
        
        String[] hex_converted = {get_hex_string(b0), get_hex_string(b1)}; 
        
        return hex_converted;
    }

    /**
     * takes a byte and returns the Hex value in a string form
     * @param b the byte
     * @return  a hex string
     */
    public String get_hex_string(byte b){

        char[] hex = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

        char[] the_hex_output = new char[2];

        the_hex_output[ 0 ] = hex[ ( Byte.toUnsignedInt(b)) >> 4 ];
        the_hex_output[ 1 ] = hex[ ( Byte.toUnsignedInt(b)) & 0x0F ];

        return new String(the_hex_output);
    }

    /**
     * prints the Ethernet header
     * @param pkt_byte_array 
     */
    public void print_eth_header(byte[] pkt_byte_array){

        System.out.println("------ ETHERNET HEADER -----");

        //Packet size
        byte len_part_1 = pkt_byte_array[16];
        byte len_part_2 = pkt_byte_array[17];
        byte total_pkt_length = combine_bytes(len_part_1, len_part_2);

        byte[] ipver_and_headerlen_info = split_the_byte( pkt_byte_array[14] ); 

        byte header_length_indicator = ipver_and_headerlen_info[1];

        int total_length = (((int) header_length_indicator) * 4) + ((int) total_pkt_length);

        System.out.println("ETH: " + "Packet Size = " + total_length + " bytes");



        //MAC adddresses
        String[] dest_mac = { get_hex_string(pkt_byte_array[0]), get_hex_string(pkt_byte_array[1]), 
                                get_hex_string(pkt_byte_array[2]), get_hex_string(pkt_byte_array[3]), 
                                get_hex_string(pkt_byte_array[4]), get_hex_string(pkt_byte_array[5]) 
        };
        
        String[] src_mac = { get_hex_string(pkt_byte_array[6]), get_hex_string(pkt_byte_array[7]), 
                                get_hex_string(pkt_byte_array[8]), get_hex_string(pkt_byte_array[9]), 
                                get_hex_string(pkt_byte_array[10]), get_hex_string(pkt_byte_array[11]) 
        };
        
        System.out.print("ETH: " + "Destination = ");

        for(int i = 0; i<6; i++ ){

            System.out.print(dest_mac[i]);
            
            if (i != 5){
                System.out.print(" : ");
            }
        }

        System.out.println();

        System.out.print("ETH: " + "Source = ");

        for(int i = 0; i<6; i++ ){

            System.out.print(src_mac[i]);
            
            if (i != 5){
                System.out.print(" : ");
            }
        }

        System.out.println();


        //Ethernet type
        System.out.println("ETH: " + "Ether Type = " + get_hex_string(pkt_byte_array[12]) + get_hex_string(pkt_byte_array[13]) );

    }


    /**
     * prints the IP header
     * @param pkt_byte_array
     */
    public void ip_header(byte[] pkt_byte_array){

        System.out.println("------ IP HEADER -----");


        //IP version
        byte[] ipver_and_headerlen_info = split_the_byte( pkt_byte_array[14] );

        System.out.println("IP: " + "Version = " + get_hex_string(ipver_and_headerlen_info[0]));


        //header length
        ip_header_length = ( (int)ipver_and_headerlen_info[1] ) * 4;

        if (ip_header_length > 20){

            ip_options = true;
        } 

        System.out.println("IP: " + "Header length = " + ip_header_length + " bytes");

        
        
        //DSCP
        String[] dscp_value = get_dscp_values(pkt_byte_array[15]);

        System.out.println("IP: " + "DSCP = 0x" + dscp_value[0] + dscp_value[1]);

        byte enc_bits = (byte) ((int)pkt_byte_array[15] & 0x03);



        //ECN
        System.out.print("IP: " + "ECN = " + enc_bits);

        if( (int)enc_bits == 0){
            System.out.println(" (not ECN capable)");
        }

        else if ( (int)enc_bits == 1){
            System.out.println(" (ECN capable end-hosts ECN(0) )");
        }

        else if ( (int)enc_bits == 2){
            System.out.println(" (ECN capable end-hosts ECN(1) )");
        }

        else if ( (int)enc_bits == 3){
            System.out.println(" (Congestion encountered)");
        }

        
        
        //Identification
        int total_length = Byte.toUnsignedInt(combine_bytes(pkt_byte_array[16], pkt_byte_array[17]));

        System.out.println("IP: " + "Total length = " + total_length + " bytes" );

        int identification = ( ( Byte.toUnsignedInt( pkt_byte_array[18])) << 8 ) | (Byte.toUnsignedInt(pkt_byte_array[19]));

        System.out.println("IP: " + "Identification = " + identification);

        
        
        //Fragmentation
        byte[] fragment_flags = { (byte) ( ((int)pkt_byte_array[20]) >> 7), 
                                    (byte) ((( (int)pkt_byte_array[20]) >> 6) & 0x01), 
                                    (byte) ((( (int)pkt_byte_array[20]) >> 5) & 0x01)  
        };

        String fragmentation_flags_hex = get_hex_string( (byte)(( (int)pkt_byte_array[20]) >> 5));

        System.out.println("IP: " + "Flags = 0x" + fragmentation_flags_hex);

        if ((int)fragment_flags[1] == 0 ){
            System.out.println("IP: " + "    .0.. ....= " + "Ok to fragment");
        } 

        else if ((int)fragment_flags[1] == 1 ){
            System.out.println("IP: " + "    .1.. ....= " + "Do not fragment");
        }

        if ((int)fragment_flags[2] == 0 ){
            System.out.println("IP: " + "    ..0. ....= " + "Last fragment");
        } 

        else if ((int)fragment_flags[2] == 1 ){
            System.out.println("IP: " + "    ..1. ....= " + "More fragments");  
        }

        int fragmentation_offset = (((Byte.toUnsignedInt(pkt_byte_array[20])) & 0x1F) << 8) | (Byte.toUnsignedInt(pkt_byte_array[21]));

        System.out.println("IP: " + "Fragmentation offset = " + fragmentation_offset + " bytes");



        //TTL
        int time_to_live =Byte.toUnsignedInt(pkt_byte_array[22]);

        System.out.println("IP: " + "Time to live = " + time_to_live + " seconds/hop");



        //Protocol
        int protocol = (int) pkt_byte_array[23];

        if (protocol == 1){

            System.out.println("IP: " + "Protocol = " + protocol + " ICMP" );
        }

        else if (protocol == 17){

            System.out.println("IP: " + "Protocol = " + protocol + " UDP" );
        }

        else if (protocol == 6){

            System.out.println("IP: " + "Protocol = " + protocol + " TCP" );
        }

        else{

            System.out.println("IP: " + "Protocol = " + protocol + " (Unknown)" );
        }




        //Header checksum
        System.out.println("IP: " + "Header Checksum = 0x" + get_hex_string(pkt_byte_array[24]) + get_hex_string(pkt_byte_array[25]) );

        


        //Addresses
        int[] src_addr = {Byte.toUnsignedInt(pkt_byte_array[26]), Byte.toUnsignedInt(pkt_byte_array[27]), 
                            Byte.toUnsignedInt(pkt_byte_array[28]), Byte.toUnsignedInt(pkt_byte_array[29]) 
        };
        
        int[] dest_addr = { Byte.toUnsignedInt(pkt_byte_array[30]), Byte.toUnsignedInt(pkt_byte_array[31]), 
                            Byte.toUnsignedInt(pkt_byte_array[32]), Byte.toUnsignedInt(pkt_byte_array[33]), 
        };

        System.out.print("IP: " + "Source address = ");

        for(int i = 0; i<4; i++ ){

            System.out.print(src_addr[i]);
            
            if (i != 3){
                System.out.print(".");
            }
        }

        System.out.println();

        System.out.print("IP: " + "Destination addresss = ");

        for(int i = 0; i<4; i++ ){

            System.out.print(dest_addr[i]);
            
            if (i != 3){
                System.out.print(".");
            }
        }

        System.out.println("");



        //options
        if (ip_options == true){
            System.out.println("IP: Options = Yes");
        }

        else if(ip_options == false){
            System.out.println("IP: Options = No");
        }
        
    }



    /**
     * prints the UDP header
     * @param pkt_byte_array
     */
    public void udp_header(byte[] pkt_byte_array){

        System.out.println("----- UDP -----");

        //calculate the index offset needed when IP has options
        int index = 0;

        if (ip_options == true){
            index = ip_header_length - 20;
        }


        //PORTS
        int source_port = ( ( Byte.toUnsignedInt( pkt_byte_array[index + 34])) << 8 ) | (Byte.toUnsignedInt(pkt_byte_array[index + 35]));

        System.out.println("UDP: Source port = " + source_port);

        int dest_port = ( ( Byte.toUnsignedInt( pkt_byte_array[index + 36])) << 8 ) | (Byte.toUnsignedInt(pkt_byte_array[index + 37]));

        System.out.println("UDP: Destination port = " + dest_port);



        //Length
        int udp_length = Byte.toUnsignedInt(combine_bytes(pkt_byte_array[index + 38], pkt_byte_array[index + 39]));

        System.out.println("UDP: length = " + udp_length);


        //Checksum
        System.out.println("UDP: " + "Checksum = 0x" + get_hex_string(pkt_byte_array[index + 40]) + get_hex_string(pkt_byte_array[index + 41]) );



        //DATA
        System.out.println("UDP: Data (first 64 bytes) = ");

        System.out.print("UDP: ");


        for(int i = 0; i < 64; i ++){

            if ((index + 42 + i) < pkt_byte_array.length){

                System.out.print( get_hex_string( pkt_byte_array[index + 42 + i]) );
                
                if ( (i%2 ==0) && ( i != 0) ){
                    System.out.print(" ");
                }

                if ( (i%6 ==0) && ( i != 0) ){
                    System.out.println("");
                    System.out.print("UDP: ");
                }
                    
            }

            else{

                break;
            }
            
        }
        
    }



    /**
     * prints the ICMP header
     * @param pkt_byte_array
     */
    public void icmp_header(byte[] pkt_byte_array){

        System.out.println("----- ICMP -----");

        //calculate the index offset needed when IP has options
        int index = 0;

        if (ip_options == true){
            index = ip_header_length - 20;
        }


        //Type
        int type =  Byte.toUnsignedInt(pkt_byte_array[index + 34]);

        System.out.print("ICMP: Type = " + type);
        
        if (type == 8){
            System.out.println(" (Echo Request)");
        }


        //Code
        int code = Byte.toUnsignedInt(pkt_byte_array[index + 35]);

        System.out.println("ICMP: Code = " + code);


        //Checksum
        System.out.println("ICMP: Checksum = 0x" + get_hex_string(pkt_byte_array[index + 36]) + get_hex_string(pkt_byte_array[index + 37]) );

    }



    /**
     * prints the TCP header
     * @param pkt_byte_array
     */
    public void tcp_header(byte[] pkt_byte_array){

        System.out.println("----- TCP -----");

        //calculate the index offset needed when IP has options
        int index = 0;

        if (ip_options == true){
            index = ip_header_length - 20;
        }


        //Ports
        int source_port = ( ( Byte.toUnsignedInt( pkt_byte_array[index + 34])) << 8 ) | (Byte.toUnsignedInt(pkt_byte_array[index + 35]));

        System.out.println("TCP: Source port = " + source_port);

        int dest_port = ( ( Byte.toUnsignedInt( pkt_byte_array[index + 36])) << 8 ) | (Byte.toUnsignedInt(pkt_byte_array[index + 37]));

        System.out.println("TCP: Destination port = " + dest_port);



        //Sequence Number
        long seq_number = (((Byte.toUnsignedLong(pkt_byte_array[index + 38]))<<24) | (((Byte.toUnsignedLong(pkt_byte_array[index + 39])) << 16))
                 | ((Byte.toUnsignedLong(pkt_byte_array[index + 40]))<<8) | (((Byte.toUnsignedLong(pkt_byte_array[index + 41])))));

        System.out.println("TCP: Sequence Number = " + seq_number);



        //Aknowledgement Number
        long aknow_number = (((Byte.toUnsignedLong(pkt_byte_array[index + 42]))<<24) | (((Byte.toUnsignedLong(pkt_byte_array[index + 43])) << 16))
                 | ((Byte.toUnsignedLong(pkt_byte_array[index + 44]))<<8) | (((Byte.toUnsignedLong(pkt_byte_array[index + 45])))));

        System.out.println("TCP: Aknowledgement Number = " + aknow_number);



        //Data Offset
        int data_offset = (Byte.toUnsignedInt(pkt_byte_array[index + 46]) >> 4);

        System.out.println("TCP: Data offset = " + data_offset + "");



        //Flags
        byte[] flags = { (byte) ((((int)pkt_byte_array[index + 47]) & 0x20)>>5), (byte) ( (((int)pkt_byte_array[index + 47]) & 0x10) >> 4), 
            (byte) ( (((int)pkt_byte_array[index + 47]) & 0x08)>>3), (byte) ( (((int)pkt_byte_array[index + 47]) & 0x04)>>2), 
            (byte) ( (((int)pkt_byte_array[index + 47]) & 0x02)>>1), (byte) ( ((int)pkt_byte_array[index + 47]) & 0x01)
        };

        System.out.println("TCP: Flags = 0x" + get_hex_string(pkt_byte_array[47]) );

        if ( (int) flags[0] == 0){

            System.out.println("TCP:       = .." + flags[0] + ". ...." + " No Urgent Pointer");

        }

        else  if ( (int) flags[0] == 1){

            System.out.println("TCP:       = .." + flags[0] + ". ...." + " Urgent Pointer");

        }

        if ( (int) flags[1] == 0){

            System.out.println("TCP:       = ..." + flags[1] + " ...." + " No Aknowledgement");

        }

        else  if ( (int) flags[1] == 1){

            System.out.println("TCP:       = ..." + flags[1] + " ...." + " Aknowledgement");

        }

        if ( (int) flags[2] == 0){

            System.out.println("TCP:       = .... " + flags[2] + "..." + " No Push");

        }

        else  if ( (int) flags[2] == 1){

            System.out.println("TCP:       = .... " + flags[2] + "..." + " Push");

        }

        if ( (int) flags[3] == 0){

            System.out.println("TCP:       = .... ." + flags[3] + ".." + " No Reset");

        }

        else  if ( (int) flags[3] == 1){

            System.out.println("TCP:       = .... ." + flags[3] + ".." + " Reset");

        }

        if ( (int) flags[4] == 0){

            System.out.println("TCP:       = .... .." + flags[4] + "." + " No Synchronization");

        }

        else  if ( (int) flags[4] == 1){

            System.out.println("TCP:       = .... .." + flags[4] + "." + " Synchronization");

        }

        if ( (int) flags[5] == 0){

            System.out.println("TCP:       = .... ..." + flags[5] + " No Fin");

        }

        else  if ( (int) flags[5] == 1){

            System.out.println("TCP:       = .... ..." + flags[5] + " Fin");

        }




        //Window
        int window = (((int)pkt_byte_array[index + 48])<<8) | (pkt_byte_array[index + 49]);

        System.out.println("TCP: Window = " + window );




        //Checksum
        System.out.println("TCP: Checksum = 0x" + get_hex_string(pkt_byte_array[index + 50]) + get_hex_string(pkt_byte_array[index + 51]) );

        int urgent = (((int)pkt_byte_array[index + 52])<<8) | (pkt_byte_array[index + 53]);

        System.out.println("TCP: Urgent = " + urgent);



        //Options
        boolean tcp_options = false;

        if (data_offset*4 > 20){
            System.out.println("TCP: Options = Yes");
            tcp_options = true;

        }

        else {
            System.out.println("TCP: Options = No");

        }




        //DATA
        if (tcp_options == true){
            
            int offset = data_offset*4 - 20 ;

            System.out.print("TCP: Data (First 64 bytes) ");

            for(int i = 0; i < 64; i ++){

                if ((index + 55 + i + offset) < pkt_byte_array.length){
    
                    System.out.print( get_hex_string( pkt_byte_array[index + 55 + i + offset]) );
                    
                    if ( (i%2 ==0) && ( i != 0) ){
                        System.out.print(" ");
                    }
    
                    if ( (i%6 ==0) && ( i != 0) ){
                        System.out.println("");
                        System.out.print("TCP: ");
                    }
                        
                }
    
                else{
    
                    break;
                }
                
            }

        }

        else{

            System.out.print("TCP: Data (First 64 bytes) ");

            for(int i = 0; i < 64; i ++){

                if ((index + 55 + i) < pkt_byte_array.length){
    
                    System.out.print( get_hex_string( pkt_byte_array[index + 55 + i]) );
                    
                    if ( (i%2 ==0) && ( i != 0) ){
                        System.out.print(" ");
                    }
    
                    if ( (i%6 ==0) && ( i != 0) ){
                        System.out.println("");
                        System.out.print("TCP: ");
                    }
                        
                }
    
                else{
    
                    break;
                }
                
            }
        }


    }


    public static void main(String[] args) {

        

        if (args.length != 0){

            String pkt_name;

            pkt_name = args[0];

            pktanalyzer obj = new pktanalyzer();

            byte[] pkt = obj.read_packet(pkt_name);

            obj.print_eth_header(pkt);
            System.out.println("");
            obj.ip_header(pkt);
            System.out.println("");

            if( (Byte.toUnsignedInt(pkt[23]) == 1 )){
                obj.icmp_header(pkt);
            }

            else if( (Byte.toUnsignedInt(pkt[23]) == 6)){
                obj.tcp_header(pkt);

            }

            else if( (Byte.toUnsignedInt(pkt[23]) == 17 )){
                obj.udp_header(pkt);
            }

        }
        
        else {

            String pkt_name;

            Scanner a = new Scanner(System.in);
            try {
                System.out.println("Enter file name: ");

                pkt_name = a.nextLine();

                pktanalyzer obj = new pktanalyzer();

                byte[] pkt = obj.read_packet(pkt_name);

                obj.print_eth_header(pkt);
                System.out.println("");
                obj.ip_header(pkt);
                System.out.println("");
        
                if( (Byte.toUnsignedInt(pkt[23]) == 1 )){
                    obj.icmp_header(pkt);
                }
        
                else if( (Byte.toUnsignedInt(pkt[23]) == 6)){
                    obj.tcp_header(pkt);
        
                }
        
                else if( (Byte.toUnsignedInt(pkt[23]) == 17 )){
                    obj.udp_header(pkt);
                }

            } catch (Exception e) {
                System.out.println(e);
            }

            a.close();
            

        }
        
        

    }

    


} 