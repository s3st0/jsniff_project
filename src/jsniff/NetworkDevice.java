package jsniff;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class NetworkDevice {
	public List<PcapIf> DeviceList;
	public StringBuilder ErrorBuffer;
	
	//Find Network Device Automatically
	@SuppressWarnings("deprecation")
	public void FindNetworkDevice(){
		DeviceList = new ArrayList<PcapIf>();
		this.ErrorBuffer = new StringBuilder();
		
		int r = Pcap.findAllDevs(DeviceList, ErrorBuffer);
		if(r == Pcap.NOT_OK || DeviceList.isEmpty())
			System.err.printf("Can not read Device list %s",ErrorBuffer.toString());
		
	}
	
	//Show Network Device List 
	public void ShowNetworkDevice(){
		int i = 0;
		for(PcapIf device : DeviceList){
			String Description = (device.getDescription() != null) ? device.getDescription() : "No Description available";
			System.out.printf("#%d : %s [%s] \n", i++, device.getName(), Description);
		}
	}

	//Show Local IP Address
	public void ShowLocalIP(){
		String localIP = null;
		try {
			localIP = InetAddress.getLocalHost().getHostAddress();
			System.out.println("host IP :" +localIP);
		} catch (UnknownHostException e) {
			e.printStackTrace();
			System.out.println("host IP :" +localIP);
		}
	}
	
	//Get Local IP Address
	public byte[] GetLocalIP() throws UnknownHostException{
		return InetAddress.getLocalHost().getAddress();
	}
	
	public void ShowLocalNetworkDevice() {
		String localDevice = null;
		try {
			localDevice = InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Local Device Name : " +localDevice);
	}
	
	public void ShowAllNetworkDeviceProperty() {
		for(int i =0 ; i< DeviceList.size(); i++)
			System.out.println(DeviceList.get(i));
	}
	
}
