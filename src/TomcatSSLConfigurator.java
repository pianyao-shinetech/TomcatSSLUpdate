import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class TomcatSSLConfigurator {

	private static final String SERVER_XML_PATH = System.getenv("SERVER_XML_PATH");
	private static final String KEYSTORE_PATH = System.getenv("KEYSTORE_PATH");
	private static final String KEYSTORE_PASSWORD = System.getenv("KEYSTORE_PASSWORD");
	private static final String CERTIFICATE_PATH = System.getenv("CERTIFICATE_PATH");
	private static final String TOMCAT_HOME = System.getenv("TOMCAT_HOME");
	private static final String SSL_PORT = System.getenv("SSL_PORT");
	private static final String HTTP_PORT = System.getenv("HTTP_PORT");

	private static final int SUCCESS = 0;
	private static final int ERROR_ENVIRONMENT = 1;
	private static final int ERROR_PERMISSION = 2;
	private static final int ERROR_BACKUP = 3;
	private static final int ERROR_KEYTOOL = 4;
	private static final int ERROR_STOP_TOMCAT = 5;
	private static final int ERROR_CONFIGURE_SSL = 6;
	private static final int ERROR_START_TOMCAT = 7;

	public static void main(final String[] args) throws IOException, InterruptedException {
		// TODO Spring Batch is also an option but too heavy for this
		// Create a list of Suppliers, where each represents a method that returns an integer
		TomcatSSLConfigurator instance = new TomcatSSLConfigurator();
		List<Supplier<Integer>> steps = Arrays.asList(
				instance::checkEnvironmentVariables,
				instance::checkFilePermissions,
				instance::backupServerXml,
				instance::createOrUpdateKeystore,
				instance::stopTomcat,
				instance::configureSSL,
				instance::startTomcat
		);
		int result = executeInChain(steps);
		if (result >= ERROR_CONFIGURE_SSL) {
			// Restore server.xml from backup if error occurred during/after the update
			instance.restoreServerXml();
		}
		if (result >= ERROR_STOP_TOMCAT) {
			instance.startTomcat();
		}
		if (result == SUCCESS) {
			System.out.println("SSL/TLS configuration updated and tomcat restarted successfully.");
			instance.deleteServerXmlBackup();
			// TODO see if we can/should remove old cert from keystore
		}
		System.exit(result);
	}

	private static int executeInChain(List<Supplier<Integer>> methods) {
		for (Supplier<Integer> method : methods) {
			int result = method.get();
			if (result != SUCCESS) {
				return result; // Stop the chain and return the result if non-zero
			}
		}
		return SUCCESS; // Return 0 if all methods return 0
	}

	private int checkEnvironmentVariables() {
		System.out.println("Checking environment variables...");
		boolean passed = SERVER_XML_PATH != null && !SERVER_XML_PATH.isBlank() &&
				KEYSTORE_PATH != null && !KEYSTORE_PATH.isBlank() &&
				KEYSTORE_PASSWORD != null && !KEYSTORE_PASSWORD.isBlank() &&
				CERTIFICATE_PATH != null && !CERTIFICATE_PATH.isBlank() &&
				TOMCAT_HOME != null && !TOMCAT_HOME.isBlank() &&
				SSL_PORT != null && !SSL_PORT.isBlank() &&
				HTTP_PORT != null && !HTTP_PORT.isBlank();
		if (passed) {
			return SUCCESS;
		} else {
			System.err.println("Required environment variables are missing.");
			return ERROR_ENVIRONMENT;
		}
	}

	private int checkFilePermissions() {
		System.out.println("Checking file permissions...");
		boolean passed = checkFilePermission(SERVER_XML_PATH, true, false) &&
//				checkFilePermission(KEYSTORE_PATH, false, false) &&
//				checkFilePermission(CERTIFICATE_PATH, false, false) &&
				checkFilePermission(TOMCAT_HOME + "/bin/catalina.sh", false, true);
		if (passed) {
			return SUCCESS;
		} else {
			System.err.println("Permission check failed for one or more files.");
			return ERROR_PERMISSION;
		}
	}

	// TODO handle the case in which server.xml.bak exists
	private int backupServerXml() {
		File originalFile = new File(SERVER_XML_PATH);
		File backupFile = new File(SERVER_XML_PATH + ".bak");
		try {
			Files.copy(originalFile.toPath(), backupFile.toPath());
			System.out.println("server.xml is backed up successfully at " + SERVER_XML_PATH + ".bak");
			return SUCCESS;
		} catch (IOException e) {
			System.out.println("Failed to backup server.xml to " + SERVER_XML_PATH + ".bak " +
					e.getClass().getCanonicalName() + " -> " + e.getMessage());
			return ERROR_BACKUP;
		}

	}

	private void restoreServerXml() {
		try {
			Files.copy(Paths.get(SERVER_XML_PATH + ".bak"), Paths.get(SERVER_XML_PATH));
			System.out.println("Restored server.xml from backup.");
		} catch (IOException e) {
			System.err.println("Failed to restore server.xml from backup: " +
					e.getClass().getCanonicalName() + " -> " + e.getMessage());
		}
	}

	private void deleteServerXmlBackup() {
		File backupFile = new File(SERVER_XML_PATH + ".bak");
		if (backupFile.delete()) {
			System.out.println("server.xml.bak is deleted.");
		} else {
			System.err.println("Failed to delete server.xml.bak");
		}
	}

	private int createOrUpdateKeystore()  {
		System.out.println("Creating or updating keystore with keytool...");
		/* Refer to official tomcat document about generating local self-signed Certificate and CSR to get a Certificate
		 https://tomcat.apache.org/tomcat-10.1-doc/ssl-howto.html#Installing_a_Certificate_from_a_Certificate_Authority
		 if this also needs being included in the whole process.

		 keytool -genkey -alias tomcat -keyalg RSA -keystore <KEYSTORE_PATH> -storepass <KEYSTORE_PASSWORD> -noprompt
		 keytool -certreq -keyalg RSA -alias tomcat -file certreq.csr -keystore <your_keystore_filename>
		*/

		/* Refer to official tomcat document about importing the Certificate into the Keystore
		 https://tomcat.apache.org/tomcat-10.1-doc/ssl-howto.html#Importing_the_Certificate
		 keytool -import -alias root -keystore <KEYSTORE_PATH> -trustcacerts -file <filename_of_the_chain_certificate>
		 (above may not necessarily be included)
		 keytool -import -alias tomcat -keystore <KEYSTORE_PATH> -file <CERTIFICATE_PATH>
		 likely:
		 String keytoolCommand = String.format("keytool -import -file %s -keystore %s -alias tomcat -storepass %s -noprompt",
				CERTIFICATE_PATH, KEYSTORE_PATH, KEYSTORE_PASSWORD);
		 */

		// For the demo purpose, we just create a local keystore and use it: keytool -genkey -alias tomcat -keyalg RSA
		//    -keystore <your_keystore_filename>
		String keytoolCommand = String.format(
				"$JAVA_HOME/bin/keytool -genkey -alias tomcat -keyalg RSA -keystore %s -storepass %s " +
						"-dname \"CN=Yao Pian, OU=Dev Unit, O=Yao Company, L=Apex, ST=NC, C=US\"",
				KEYSTORE_PATH, KEYSTORE_PASSWORD);

		ProcessBuilder processBuilder = new ProcessBuilder("bash", "-c", keytoolCommand);
		processBuilder.redirectErrorStream(true);
		try {
			Process process = processBuilder.start();
			int exitCode = process.waitFor();
			if (exitCode != SUCCESS) {
				System.err.println("Failed to execute keytool command. Exit code: " + exitCode);
				return ERROR_KEYTOOL;
			}
			return SUCCESS;
		} catch (Exception e) {
			System.err.println("Error: " +
					e.getClass().getCanonicalName() + " -> " + e.getMessage());
			return ERROR_KEYTOOL;
		}
	}

	private int configureSSL() {
		System.out.println("Updating server.xml SSL configuration...");
		try {
			File xmlFile = new File(SERVER_XML_PATH);
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(xmlFile);
//			doc.getDocumentElement().normalize();

			NodeList connectorList = doc.getElementsByTagName("Connector");
			Element sslConnector = findHTTPConnector(connectorList, true);
			Element httpConnector = findHTTPConnector(connectorList, false);
			if (httpConnector == null) {
				throw new Exception("Invalid server.xml file - HTTP Connector doesn't exist");
			}
			boolean sslConnectorExists = sslConnector != null;
			Element cert = null;

			if (sslConnectorExists) {
				System.out.println("SSL/TLS configuration already exists. Updating...");
				cert = (Element) sslConnector.getElementsByTagName("Certificate").item(0);
			} else {
				System.out.println("SSL/TLS configuration doesn't exist. Creating...");
				sslConnector = doc.createElement("Connector");
				sslConnector.setAttribute("protocol", "org.apache.coyote.http11.Http11NioProtocol");
				sslConnector.setAttribute("maxThreads", "150");
				sslConnector.setAttribute("SSLEnabled", "true");
				sslConnector.setAttribute("maxParameterCount", "1000");

				// insert SSL Connector after HTTP Connector
				httpConnector.getParentNode().insertBefore(sslConnector, httpConnector.getNextSibling());

				Element upgradeProtocol = doc.createElement("UpgradeProtocol");
				upgradeProtocol.setAttribute("className", "org.apache.coyote.http2.Http2Protocol");
				sslConnector.appendChild(upgradeProtocol);

				Element sslHostConfig = doc.createElement("SSLHostConfig");
				sslConnector.appendChild(sslHostConfig);

				cert = doc.createElement("Certificate");
				cert.setAttribute("type", "RSA");
				sslHostConfig.appendChild(cert);
			}

			sslConnector.setAttribute("port", SSL_PORT);
			httpConnector.setAttribute("redirectPort", SSL_PORT);
			cert.setAttribute("certificateKeystoreFile", KEYSTORE_PATH);
			cert.setAttribute("certificateKeystorePassword", KEYSTORE_PASSWORD);

			// Write the updated content back to the server.xml file
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			DOMSource source = new DOMSource(doc);
			StreamResult result = new StreamResult(xmlFile);
			transformer.transform(source, result);
			return SUCCESS;
		} catch (Exception e) {
			System.err.println("Failed to configure SSL in server.xml: " + e.getClass().getCanonicalName() + " -> " + e.getMessage());
			return ERROR_CONFIGURE_SSL;
		}
	}

	private int stopTomcat() {
		System.out.println("Stopping Tomcat...");
		String shutdownCommand = String.format("%s/bin/catalina.sh stop", TOMCAT_HOME);

		ProcessBuilder shutdownProcessBuilder = new ProcessBuilder("bash", "-c", shutdownCommand);
		shutdownProcessBuilder.redirectErrorStream(true);
		try {
			Process shutdownProcess = shutdownProcessBuilder.start();
			int exitCode = shutdownProcess.waitFor();
			if (exitCode != SUCCESS) {
				System.err.println("Failed to stop Tomcat. Exit code: " + exitCode);
				return ERROR_STOP_TOMCAT;
			}
			return SUCCESS;
		} catch (Exception e) {
			System.err.println("Error: " + e.getClass().getCanonicalName() + " -> " + e.getMessage());
			return ERROR_STOP_TOMCAT;
		}
	}

	private int startTomcat() {
		System.out.println("Starting Tomcat...");
		String startupCommand = String.format("%s/bin/catalina.sh start", TOMCAT_HOME);

		ProcessBuilder startupProcessBuilder = new ProcessBuilder("bash", "-c", startupCommand);
		startupProcessBuilder.redirectErrorStream(true);
		try {
			Process startupProcess = startupProcessBuilder.start();
			int exitCode =  startupProcess.waitFor();
			if (exitCode != SUCCESS) {
				System.err.println("Failed to start Tomcat. Exit code: " + exitCode);
				return ERROR_START_TOMCAT;
			}
			return SUCCESS;
		} catch (Exception e) {
			System.err.println("Error: " + e.getClass().getCanonicalName() + " -> " + e.getMessage());
			return ERROR_START_TOMCAT;
		}

	}

	private boolean checkFilePermission(
			final String filePath,
			final boolean checkWritePermission,
			final boolean checkExecutionPermission) {

		File file = new File(filePath);
		return file.exists()
				&& file.canRead()
				&& (checkWritePermission ? file.canWrite() : true)
				&& (checkExecutionPermission ? file.canExecute() : true);
	}

	private Element findHTTPConnector(final NodeList connectorList, final boolean ssl) {
		Element httpConnector = null;
		for (int i = 0; i < connectorList.getLength(); i++) {
			Element connector = (Element) connectorList.item(i);
			if (!ssl &&
					connector.getAttribute("port").equals(HTTP_PORT) &&
					connector.getAttribute("protocol").equals("HTTP/1.1")) {

				httpConnector = connector;
				break;
			}
			if (ssl &&
					connector.hasAttribute("SSLEnabled") &&
					"true".equals(connector.getAttribute("SSLEnabled"))) {
				httpConnector = connector;
				break;
			}
		}
		return httpConnector;
	}

}
