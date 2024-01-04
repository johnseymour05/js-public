package com.seymour.tlsnio;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.net.*;
import javax.net.ssl.*;

public class SSLNIOEchoServer {

	SSLContext context;
	ServerSocketChannel ssc;
	Selector sel;

	public SSLNIOEchoServer() throws Exception {
		// Create the SSLContext
		this.context = SSLContext.getInstance("TLSv1.2"); // Initialize KMF ...
        context.init(createKeyManagers("./src/main/resources/client.jks", "storepass", "keypass"), createTrustManagers("./src/main/resources/trustedCerts.jks", "storepass"), new SecureRandom());


		// Start the server
		this.ssc = ServerSocketChannel.open();
		ssc.configureBlocking(false);
		SocketAddress port = new InetSocketAddress(5556);
		ssc.socket().bind(port);		
		System.out.println("Server: listening at " + ssc);
		this.sel = Selector.open();
		ssc.register(sel, SelectionKey.OP_ACCEPT);
	}

	public void run() throws IOException {
		// Selector loop
		int count;
		while (sel.keys().size() > 0) {
			try {
				count = sel.select(30 * 1000);
				if (count < 0) {
					System.out.println("Server: select timeout");
					continue;
				}
			} catch (IOException exc) {
				exc.printStackTrace();
				sel.close();
				ssc.close();
				return;
			}
			System.out.println("Server: select count=" + count);
			Set selKeys = sel.selectedKeys();
			Iterator it = selKeys.iterator();
			// process ready keys
			while (it.hasNext()) {
				SelectionKey sk = (SelectionKey) it.next();
				it.remove();
				if (!sk.isValid())
					continue;
				try {
					if (sk.isAcceptable())
						handleAccept(sk);
					if (sk.isReadable())
						handleRead(sk);
					if (sk.isWritable())
						handleWrite(sk);
				} catch (IOException exc) {
					exc.printStackTrace();
					sk.channel().close();
				}
			}
		}
	}

	void handleAccept(SelectionKey sk) throws IOException {
		ServerSocketChannel ssc = (ServerSocketChannel) sk.channel();
		SocketChannel sc = ssc.accept();
		if (sc != null) {
			System.out.println("Server: accepted " + sc);
			sc.configureBlocking(false);
			// Create an SSL engine for this connection
			SSLEngine engine = context.createSSLEngine("localhost", sc.socket().getPort());
			// This is the server end
			engine.setUseClientMode(false);
			// Create engine manager for the channel & engine
			SSLEngineManager mgr = new SSLEngineManager(sc, engine);
			// Register for OP_READ with mgr as attachment
			sc.register(sel, SelectionKey.OP_READ, mgr);
		}
	}

	void handleRead(SelectionKey sk) throws IOException {
		SSLEngineManager mgr = (SSLEngineManager) sk.attachment();
		SSLEngine engine = mgr.getEngine();
		ByteBuffer request = mgr.getAppRecvBuffer();
		System.out.println("Server: reading");
		int count = mgr.read();
		System.out.println("Server: read count=" + count + " request=" + request);
		if (count < 0) {
			// client has closed
			mgr.close();
			// finished with this key
			sk.cancel();
			// finished with this test actually
			ssc.close();
		} else if (request.position() > 0) {
			// client request
			System.out.println("Server: read " + new String(request.array(), 0, request.position()));
			ByteBuffer reply = mgr.getAppSendBuffer();
			request.flip();
			reply.put(request);
			request.compact();
			handleWrite(sk);
		}
	}

	void handleWrite(SelectionKey sk) throws IOException {
		SSLEngineManager mgr = (SSLEngineManager) sk.attachment();
		ByteBuffer reply = mgr.getAppSendBuffer();
		System.out.println("Server: writing " + reply);
		int count = 0;
		while (reply.position() > 0) {
			reply.flip();
			count = mgr.write();
			reply.compact();
			if (count == 0)
				break;
		}
		if (reply.position() > 0) {
			// short write:
			// Register for OP_WRITE and come back here when ready
			sk.interestOps(sk.interestOps() | SelectionKey.OP_WRITE);
		} else {
			// Write succeeded, don’t need OP_WRITE any more
			sk.interestOps(sk.interestOps() & ~SelectionKey.OP_WRITE);
		}
	}

	// Main program
	public static void main(String[] args) throws Exception {
		 System.setProperty("javax.net.debug","all");
		// TODO adjust these values to suit your local system. // These values are for
		// the JDK SSL samples ‘testkeys’.
		new SSLNIOEchoServer().run();
		System.out.println("Exiting.");
	}
	
    protected KeyManager[] createKeyManagers(String filepath, String keystorePassword, String keyPassword) throws Exception {
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
    
    protected TrustManager[] createTrustManagers(String filepath, String keystorePassword) throws Exception {
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