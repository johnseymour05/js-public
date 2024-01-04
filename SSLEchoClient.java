package com.seymour.tlsnio;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.net.*;
import javax.net.ssl.*;

class SSLEchoClient extends Thread {
	SSLSocket socket;

	SSLEchoClient(SSLContext context, String host, int port) throws IOException {
		this.socket = (SSLSocket) context.getSocketFactory().createSocket(host, port);
	}

	public void run() {
		try {
			int count;
			byte[] buffer = new byte[8192];
			// send request
			socket.getOutputStream().write("hello".getBytes());
			// handshake before read
			socket.startHandshake();
			// read reply
			count = socket.getInputStream().read(buffer);
			System.out.println("client: (1) got " + new String(buffer, 0, count) + ":" + count);
			// get a new session & do a full handshake
			socket.getSession().invalidate();
			socket.startHandshake();
			// send another request
			socket.getOutputStream().write("hello again after new handshake".getBytes());
			// Do a partial handshake before reading the reply
			socket.startHandshake();
			// read reply
			count = socket.getInputStream().read(buffer);
			System.out.println("client: (2) got " + new String(buffer, 0, count) + ":" + count);
		} catch (IOException exc) {
			exc.printStackTrace();
		} finally {
			try {
				socket.close();
				System.out.println("client: socket closed");
			} catch (IOException exc) {
				// ignored
			}
		}
	}
	
	public static void main(String[] args) throws Exception {
		 System.setProperty("javax.net.debug","all");

		SSLContext context = SSLContext.getInstance("TLSv1.2"); // Initialize KMF ...
        context.init(createKeyManagers("./src/main/resources/client.jks", "storepass", "keypass"), createTrustManagers("./src/main/resources/trustedCerts.jks", "storepass"), new SecureRandom());

		new SSLEchoClient(context, "localhost", 5556).run();
	}
	
    protected static KeyManager[] createKeyManagers(String filepath, String keystorePassword, String keyPassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        InputStream keyStoreIS = new FileInputStream(filepath);
        try {
            keyStore.load(keyStoreIS, keystorePassword.toCharArray());
        } finally {
            if (keyStoreIS != null) {
                keyStoreIS.close();
            }
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, keyPassword.toCharArray());
        return kmf.getKeyManagers();
    }
    
    protected static TrustManager[] createTrustManagers(String filepath, String keystorePassword) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        InputStream trustStoreIS = new FileInputStream(filepath);
        try {
            trustStore.load(trustStoreIS, keystorePassword.toCharArray());
        } finally {
            if (trustStoreIS != null) {
                trustStoreIS.close();
            }
        }
        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);
        return trustFactory.getTrustManagers();
    }
}