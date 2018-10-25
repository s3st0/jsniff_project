package jsniff;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderType;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
public class Packetcapture {
	public int snapByteLength = 64 * 1024; //default : Not divide packet
	public int timeout;
	public int flags;
	public Pcap pcap;
	public PcapIf DeviceHandler;
	StringBuilder ErrorBuffer;
	
	public void setMode(String ModeType){
		switch(ModeType){
		case "promisc":
			flags = Pcap.MODE_PROMISCUOUS;
		case "non_promisc":
			flags = Pcap.MODE_NON_PROMISCUOUS;
		}
	}
	
	public void setMode(int ModeType){
		flags = ModeType;
	}
	
	public int getMode(){
		return flags;
	}
	
	public void setTimeout(int seconds){
		timeout = seconds * 1000;
	}
	
	public void setSnapByteLength(int length){
		snapByteLength = length * 1024;
	}
	
	public void setDeviceHandler(PcapIf devicehandler){
		DeviceHandler = devicehandler;
	}
	
	// Analysis meaningful data in packet 
	public void translatePacket(PcapPacket pkt){
		Ethernet eth = new Ethernet();
		Ip4 ip = new Ip4();
		Tcp tcp = new Tcp();
		Payload payload = new Payload();

		System.out.printf("[ Frame Number : %d ] \n" , pkt.getFrameNumber());
		// System.out.printf("Protocol Type : %s", )
		if(pkt.hasHeader(eth)){
			System.out.printf("src MAC = %s, dst MAC = %s\n", FormatUtils.mac(eth.source()), FormatUtils.mac(eth.destination()));
		}
		
		if(pkt.hasHeader(ip)){
			System.out.printf("src IP = %s, dst IP = %s\n", FormatUtils.ip(ip.source()), FormatUtils.ip(ip.destination()));
		}
		
		if(pkt.hasHeader(tcp)){
			System.out.printf("dst tcp port = %s, dst tcp port = %s \n\n", tcp.source(),tcp.destination());
		}
		if(pkt.hasHeader(payload)){
			System.out.printf("Payload Length = %d \n", payload.getLength());
			System.out.print(payload.toHexdump());
			System.out.println("\n");
		}
		
	}
	
	public Packetcapture(String Modetype, int timeout_seconds, int snaplength, PcapIf devicehandler){
		switch(Modetype){
		case "promisc":
			flags = Pcap.MODE_PROMISCUOUS;
		case "non_promisc":
			flags = Pcap.MODE_NON_PROMISCUOUS;
		}
		timeout = timeout_seconds * 1000;
		snapByteLength = snaplength * 1024;
		DeviceHandler = devicehandler;
	}
	
	public Packetcapture(){
		// to do code 
	}
	
	public void startPacketCapture() throws InterruptedException{
		ErrorBuffer =new StringBuilder();
		Pcap pcap = Pcap.openLive(DeviceHandler.getName(), snapByteLength, flags, timeout, ErrorBuffer);
		int id = JRegistry.mapDLTToId(pcap.datalink());
		PcapHeader header = new PcapHeader(JMemory.POINTER);
		JBuffer buf = new JBuffer(JMemory.POINTER);
		
		//Continuous scan & translate 
		while(pcap.nextEx(header, buf) == Pcap.NEXT_EX_OK){
			PcapPacket pkt = new PcapPacket(header,buf);
			pkt.scan(id);
			translatePacket(pkt);
			Thread.sleep(100);
		}
		
	}
	
	public void closePcap(){
		pcap.close();
	}
}

		
