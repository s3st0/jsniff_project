package jsniff;

public class main {

	public static void main(String[] args) throws InterruptedException {
		System.out.println("Load Network Device List");
		NetworkDevice ndv = new NetworkDevice();
		ndv.FindNetworkDevice();
		ndv.ShowNetworkDevice();
		ndv.ShowLocalIP();
		ndv.ShowLocalNetworkDevice();
		ndv.ShowAllNetworkDeviceProperty();
		System.out.println("");
		System.out.printf("\nStart capturing packet with NIC Name '%s' \n\n", ndv.DeviceList.get(5).getDescription());
		
		Packetcapture captureUnit = new Packetcapture("promisc",100,64,ndv.DeviceList.get(5));
		captureUnit.startPacketCapture();
		
		
	}

}
