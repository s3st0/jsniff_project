package jsniff;

import java.io.File;

public class systemControl {
	
	//JNI 관련 참조
	public static int LoadLibFile(String filename){
		
			try{
				System.load(new File(filename).getAbsolutePath());
				System.out.println(new File("jnetpcap.dll").getAbsolutePath());
				return 0;
			}catch(UnsatisfiedLinkError e){
				return 1;
			}
		
		
	}
	
}
