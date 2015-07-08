/**
 * Appcelerator Titanium Mobile
 * Copyright (c) 2009-2013 by Appcelerator, Inc. All Rights Reserved.
 * Licensed under the terms of the Apache Public License
 * Please see the LICENSE included with this distribution for details.
 */
package org.appcelerator.titanium.util.appcresponsecache;

import android.annotation.TargetApi;
import android.os.Build;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.CacheRequest;
import java.net.CacheResponse;
import java.net.ResponseCache;
import java.net.SecureCacheResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.commons.codec.digest.DigestUtils;
import org.appcelerator.kroll.common.Log;
import org.appcelerator.titanium.TiApplication;
import org.appcelerator.titanium.util.disklrucache.DiskLruCache;
import org.appcelerator.titanium.util.disklrucache.StrictLineReader;
import org.appcelerator.titanium.util.disklrucache.Util;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class AppcResponseCache extends ResponseCache
{
	private static final int VERSION = 201105;
	private static final int ENTRY_METADATA = 0;
    private static final int ENTRY_BODY = 1;
    private static final int ENTRY_COUNT = 2;
    private final DiskLruCache cache;
    /* read and write statistics, all guarded by 'this' */
    private int writeSuccessCount;
    private int writeAbortCount;
    private int networkCount;
    private int hitCount;
    private int requestCount;
    
    ///
	
	private static final String TAG = "AppcResponseCache";

	private static final String HEADER_SUFFIX = ".hdr";
	private static final String BODY_SUFFIX   = ".bdy";
	private static final String CACHE_SIZE_KEY = "ti.android.cache.size.max";
	private static final int DEFAULT_CACHE_SIZE = 25 * 1024 * 1024; // 25MB
	private static final int INITIAL_DELAY = 10000;
	private static final int CLEANUP_DELAY = 60000;
	private static HashMap<String, ArrayList<CompleteListener>> completeListeners = new HashMap<String, ArrayList<CompleteListener>>();
	private static long maxCacheSize = 0;

	private static ScheduledExecutorService cleanupExecutor = null;
	
	public static interface CompleteListener
	{
		public void cacheCompleted(URI uri);
	}

	private static class TiCacheCleanup implements Runnable
	{
		private File cacheDir;
		private long maxSize;
		public TiCacheCleanup(File cacheDir, long maxSize)
		{
			this.cacheDir  = cacheDir;
			this.maxSize = maxSize;
		}

		// TODO @Override
		public void run()
		{
			// Build up a list of access times
			HashMap<Long, File> lastTime = new HashMap<Long, File>();
			for (File hdrFile : cacheDir.listFiles(new FilenameFilter() {
					// TODO @Override
					public boolean accept(File dir, String name) {
						return name.endsWith(HEADER_SUFFIX);
					}
				}))
			{
				lastTime.put(hdrFile.lastModified(), hdrFile);
			}
			
			// Ensure that the cache is under the required size
			List<Long> sz = new ArrayList<Long>(lastTime.keySet());
			Collections.sort(sz);
			Collections.reverse(sz);
			long cacheSize = 0;
			for (Long last : sz) {
				File hdrFile = lastTime.get(last);
				String h = hdrFile.getName().substring(0, hdrFile.getName().lastIndexOf('.')); // Hash
				File bdyFile = new File(cacheDir, h + BODY_SUFFIX);
				
				cacheSize += hdrFile.length();
				cacheSize += bdyFile.length();
				if (cacheSize > this.maxSize) {
					hdrFile.delete();
					bdyFile.delete();
				}
			}
		}
		
	}
	
	private static class TiCacheResponse extends CacheResponse {
		private Map<String, List<String>> headers;
		private InputStream istream;
		
		public TiCacheResponse(Map<String, List<String>> hdrs, InputStream istr)
		{
			super();
			headers = hdrs;
			istream = istr;
		}
		
		@Override
		public Map<String, List<String>> getHeaders()
			throws IOException
		{
			return headers;
		}
		
		@Override
		public InputStream getBody() throws IOException
		{
			return istream;
		}
	}

	private static class TiCacheOutputStream extends FileOutputStream
	{
		private URI uri;
		public TiCacheOutputStream(URI uri, File file)
			throws FileNotFoundException
		{
			super(file);
			this.uri = uri;
		}

		@Override
		public void close()
			throws IOException
		{
			super.close();
			fireCacheCompleted(uri);
		}
	}

	private static class TiCacheRequest extends CacheRequest
	{
		private URI uri;
		private File bFile, hFile;
		private long contentLength;

		public TiCacheRequest(URI uri, File bFile, File hFile, long contentLength)
		{
			super();
			this.uri = uri;
			this.bFile = bFile;
			this.hFile = hFile;
			this.contentLength = contentLength;
		}

		@Override
		public OutputStream getBody()
			throws IOException
		{
			return new TiCacheOutputStream(uri, bFile);
		}

		@Override
		public void abort()
		{
			// Only truly abort if we didn't write the whole length
			// This works around a bug where Android calls abort()
			// whenever the file is closed, successful writes or not
			if (bFile.length() != this.contentLength) {
				Log.e(TAG, "Failed to add item to the cache!");
				if (bFile.exists()) bFile.delete();
				if (hFile.exists()) hFile.delete();
			}
		}
	}

	/**
	 * Check whether the content from uri has been cached. This method is optimized for
	 * TiResponseCache. For other kinds of ResponseCache, eg. HttpResponseCache, it only
	 * checks whether the system's default response cache is set.
	 * @param uri
	 * @return true if the content from uri is cached; false otherwise.
	 */
	public static boolean peek(URI uri)
	{
		ResponseCache rcc = AppcResponseCache.getDefault();

		if (rcc instanceof AppcResponseCache) {
			// The default response cache is set by Titanium
			AppcResponseCache rc = (AppcResponseCache) rcc;
			if (rc.cacheDir == null) {
				return false;
			}
			String hash = DigestUtils.shaHex(uri.toString());
			File hFile = new File(rc.cacheDir, hash + HEADER_SUFFIX);
			File bFile = new File(rc.cacheDir, hash + BODY_SUFFIX);
			if (!bFile.exists() || !hFile.exists()) {
				return false;
			}
			return true;

		} else if (rcc != null) {
			// The default response cache is set by other modules/sdks
			return true;
		}

		return false;
	}

	/**
	 * Get the cached content for uri. It works for all kinds of ResponseCache.
	 * @param uri
	 * @return an InputStream of the cached content
	 */
	public static InputStream openCachedStream(URI uri)
	{
		ResponseCache rcc = AppcResponseCache.getDefault();

		if (rcc instanceof AppcResponseCache) {
			// The default response cache is set by Titanium
			AppcResponseCache rc = (AppcResponseCache) rcc;
			if (rc.cacheDir == null) {
				return null;
			}
			String hash = DigestUtils.shaHex(uri.toString());
			File hFile = new File(rc.cacheDir, hash + HEADER_SUFFIX);
			File bFile = new File(rc.cacheDir, hash + BODY_SUFFIX);
			if (!bFile.exists() || !hFile.exists()) {
				return null;
			}
			try {
				boolean isGZip = false;
				// Read in the headers
				try {
					Map<String, List<String>> headers = readHeaders(hFile);
					String contentEncoding = getHeader(headers, "content-encoding");
					if ("gzip".equalsIgnoreCase(contentEncoding)) {
						isGZip = true;
					}
				} catch (IOException e) {
					// continue with file read?
				}
				if (isGZip) {
					return new GZIPInputStream(new FileInputStream(bFile));
				}
				return new FileInputStream(bFile);
			} catch (FileNotFoundException e) {
				// Fallback to URL download?
				return null;
			} catch (IOException e) {
				return null;
			}

		} else if (rcc != null) {
			// The default response cache is set by other modules/sdks
			try {
				URLConnection urlc = uri.toURL().openConnection();
				urlc.setRequestProperty("Cache-Control", "only-if-cached");
				return urlc.getInputStream();
			} catch (Exception e) {
				// Not cached. Fallback to URL download.
				return null;
			}
		}

		return null;
	}

	public static void addCompleteListener(URI uri, CompleteListener listener)
	{
		synchronized (completeListeners) {
			String hash = DigestUtils.shaHex(uri.toString());
			if (!completeListeners.containsKey(hash)) {
				completeListeners.put(hash, new ArrayList<CompleteListener>());
			}
			completeListeners.get(hash).add(listener);
		}
	}

	private File cacheDir = null;
	
	private String uriToKey(URI uri) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            byte[] md5bytes = messageDigest.digest(uri.toString().getBytes(Util.UTF_8));
            return IntegralToString.bytesToHexString(md5bytes, false);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
	

	public AppcResponseCache(File cachedir, TiApplication tiApp) throws IOException {
		super();
		assert cachedir.isDirectory() : "cachedir MUST be a directory";
		cacheDir = cachedir;

		maxCacheSize = tiApp.getAppProperties().getInt(CACHE_SIZE_KEY, DEFAULT_CACHE_SIZE) * 1024;
		Log.d(TAG, "max cache size is:" + maxCacheSize, Log.DEBUG_MODE);
		
		cache = DiskLruCache.open(cachedir, VERSION, ENTRY_COUNT, maxCacheSize);

		cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
		TiCacheCleanup command = new TiCacheCleanup(cacheDir, maxCacheSize);
		cleanupExecutor.scheduleWithFixedDelay(command, INITIAL_DELAY, CLEANUP_DELAY, TimeUnit.MILLISECONDS);
	}
	
	///// Ashraf was here
	 private void abortQuietly(DiskLruCache.Editor editor) {
	        // Give up because the cache cannot be written.
	        try {
	            if (editor != null) {
	                editor.abort();
	            }
	        } catch (IOException ignored) {
	        }
	}
	 
	 public DiskLruCache getCache() {
	        return cache;
	    }
	    public synchronized int getWriteAbortCount() {
	        return writeAbortCount;
	    }
	    public synchronized int getWriteSuccessCount() {
	        return writeSuccessCount;
	    }
	 
	/// Ashraf code ends here
	    
	@Override public CacheResponse get(URI uri, String requestMethod,
	        Map<String, List<String>> requestHeaders) {
		Log.d("TiAsh", "Cache Getting");
	    String key = uriToKey(uri);
	    Log.d("TiAsh", "Cache Getting Key:"+key);
	    DiskLruCache.Snapshot snapshot;
	    Entry entry;
	    try {
	        snapshot = cache.get(key);
	        if (snapshot == null) {
	        	Log.d("TiAsh", "Cache Getting Nothing");
	            return null;
	        }
	        entry = new Entry(snapshot.getInputStream(ENTRY_METADATA));
	    } catch (IOException e) {
	        // Give up because the cache cannot be read.
	        return null;
	    }
	    if (!entry.matches(uri, requestMethod, requestHeaders)) {
	        snapshot.close();
	        return null;
	    }
	    return entry.isHttps()
	            ? new EntrySecureCacheResponse(entry, snapshot)
	            : new EntryCacheResponse(entry, snapshot);
	}
	
	@Override public CacheRequest put(URI uri, URLConnection urlConnection) throws IOException {
		Log.d("TiAsh", "Cache Putting");
		if (cacheDir == null) return null;
		
		// Make sure the cacheDir exists, in case user clears cache while app is running
		if (!cacheDir.exists()) {
			cacheDir.mkdirs();
		}		
		Log.d("TiAsh", "Cache Continue Putting");
		// Gingerbread 2.3 bug: getHeaderField tries re-opening the InputStream
		// getHeaderFields() just checks the response itself
		Map<String, List<String>> headers = makeLowerCaseHeaders(urlConnection.getHeaderFields());
		String cacheControl = getHeader(headers, "cache-control");
		if (cacheControl != null && cacheControl.matches("^.*(no-cache|no-store|must-revalidate|max-age=0).*")) {
			return null; // See RFC-2616
		}
		
		boolean skipTransferEncodingHeader = false;
		String tEncoding = getHeader(headers, "transfer-encoding");
		if (tEncoding != null && tEncoding.toLowerCase().equals("chunked")) {
			skipTransferEncodingHeader = true; // don't put "chunked" transfer-encoding into our header file, else the http connection object that gets our header information will think the data starts with a chunk length specification
		}
		
		// Form the headers and generate the content length
		String newl = System.getProperty("line.separator");
		long contentLength = getHeaderInt(headers, "content-length", 0);
		StringBuilder sb = new StringBuilder();
		for (String hdr : headers.keySet()) {
			if (!skipTransferEncodingHeader || !hdr.equals("transfer-encoding")) {
				for (String val : headers.get(hdr)) {
					sb.append(hdr);
					sb.append("=");
					sb.append(val);
					sb.append(newl);
				}
			}
		}
		if (contentLength + sb.length() > maxCacheSize) {
			Log.d("TiAsh", "Cache Not Putting Hence NUll");
			return null;
		}
		
		// Work around an android bug which gives us the wrong URI
		try {
			uri = urlConnection.getURL().toURI();
		} catch (URISyntaxException e) {}
		
        String key = uriToKey(uri);
        Log.d("TiAsh", "Cache Putting Key:"+key);
        //URI uri, RawHeaders varyHeaders, URLConnection httpConnection, String requestMethod       
        Entry entry = new Entry(uri, new RawHeaders(), urlConnection, "GET");
        DiskLruCache.Editor editor = null;
        try {
            editor = cache.edit(key);
            if (editor == null) {
                return null;
            }
            entry.writeTo(editor);
            return new CacheRequestImpl(editor);
        } catch (IOException e) {
            abortQuietly(editor);
            return null;
        }
    }



	private static Map<String, List<String>> readHeaders(File hFile) throws IOException 
	{
		// Read in the headers
		Map<String, List<String>> headers = new HashMap<String, List<String>>();
		BufferedReader rdr = new BufferedReader(new FileReader(hFile), 1024);
		for (String line=rdr.readLine() ; line != null ; line=rdr.readLine()) {
			String keyval[] = line.split("=", 2);
			if (keyval.length < 2) {
				continue;
			}
			// restore status line key that was stored in makeLowerCaseHeaders()
			if ("null".equals(keyval[0])) {
				keyval[0] = null;
			}

			if (!headers.containsKey(keyval[0])) {
				headers.put(keyval[0], new ArrayList<String>());
			}
			
			headers.get(keyval[0]).add(keyval[1]);
			
		}
		rdr.close();
		return headers;
	}
	
	protected static String getHeader(Map<String, List<String>> headers, String header)
	{
		List<String> values = headers.get(header);
		if (values == null || values.size() == 0) {
			return null;
		}
		return values.get(values.size() - 1);
	}

	protected int getHeaderInt(Map<String, List<String>> headers, String header, int defaultValue)
	{
		String value = getHeader(headers, header);
		if (value == null) {
			return defaultValue;
		}
		try {
			return Integer.parseInt(value);
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	private Map<String, List<String>> makeLowerCaseHeaders(Map<String, List<String>> origHeaders)
	{
		Map<String, List<String>> headers = new HashMap<String, List<String>>(origHeaders.size());
		for (String key : origHeaders.keySet()) {
			if (key != null) {
				headers.put(key.toLowerCase(), origHeaders.get(key));
			} else {
				//status line has null key
				headers.put("null", origHeaders.get(key));
			}
		}
		return headers;
	}


	
	public void setCacheDir(File dir)
	{
		cacheDir = dir;
	}

	private static final void fireCacheCompleted(URI uri)
	{
		synchronized (completeListeners) {
			String hash = DigestUtils.shaHex(uri.toString());
			if (completeListeners.containsKey(hash)) {
				for (CompleteListener listener : completeListeners.get(hash)) {
					listener.cacheCompleted(uri);
				}
				completeListeners.remove(hash);
			}
		}
	}
	
	 private final class CacheRequestImpl extends CacheRequest {
	        private final DiskLruCache.Editor editor;
	        private OutputStream cacheOut;
	        private boolean done;
	        private OutputStream body;
	        public CacheRequestImpl(final DiskLruCache.Editor editor) throws IOException {
	            this.editor = editor;
	            this.cacheOut = editor.newOutputStream(ENTRY_BODY);
	            this.body = new FilterOutputStream(cacheOut) {
	                @Override public void close() throws IOException {
	                    synchronized (this) {
	                        if (done) {
	                            return;
	                        }
	                        done = true;
	                        writeSuccessCount++;
	                    }
	                    super.close();
	                    editor.commit();
	                }
	                @Override
	                public void write(byte[] buffer, int offset, int length) throws IOException {
	                    // Since we don't override "write(int oneByte)", we can write directly to "out"
	                    // and avoid the inefficient implementation from the FilterOutputStream.
	                    out.write(buffer, offset, length);
	                }
	            };
	        }
	        @Override public void abort() {
	            synchronized (this) {
	                if (done) {
	                    return;
	                }
	                done = true;
	                writeAbortCount++;
	            }
	            try {
	            	cacheOut.close();
	                editor.abort();
	            } catch (IOException ignored) {
	            }
	        }
	        @Override public OutputStream getBody() throws IOException {
	            return body;
	        }
	    }
	
    private static final class Entry {
        private final String uri;
        private final RawHeaders varyHeaders;
        private final String requestMethod;
        private final RawHeaders responseHeaders;
        private final String cipherSuite;
        private final Certificate[] peerCertificates;
        private final Certificate[] localCertificates;
        /*
         * Reads an entry from an input stream. A typical entry looks like this:
         *   http://google.com/foo
         *   GET
         *   2
         *   Accept-Language: fr-CA
         *   Accept-Charset: UTF-8
         *   HTTP/1.1 200 OK
         *   3
         *   Content-Type: image/png
         *   Content-Length: 100
         *   Cache-Control: max-age=600
         *
         * A typical HTTPS file looks like this:
         *   https://google.com/foo
         *   GET
         *   2
         *   Accept-Language: fr-CA
         *   Accept-Charset: UTF-8
         *   HTTP/1.1 200 OK
         *   3
         *   Content-Type: image/png
         *   Content-Length: 100
         *   Cache-Control: max-age=600
         *
         *   AES_256_WITH_MD5
         *   2
         *   base64-encoded peerCertificate[0]
         *   base64-encoded peerCertificate[1]
         *   -1
         *
         * The file is newline separated. The first two lines are the URL and
         * the request method. Next is the number of HTTP Vary request header
         * lines, followed by those lines.
         *
         * Next is the response status line, followed by the number of HTTP
         * response header lines, followed by those lines.
         *
         * HTTPS responses also contain SSL session information. This begins
         * with a blank line, and then a line containing the cipher suite. Next
         * is the length of the peer certificate chain. These certificates are
         * base64-encoded and appear each on their own line. The next line
         * contains the length of the local certificate chain. These
         * certificates are also base64-encoded and appear each on their own
         * line. A length of -1 is used to encode a null array.
         */
        public Entry(InputStream in) throws IOException {
            try {
                StrictLineReader reader = new StrictLineReader(in, Util.UTF_8);
                uri = reader.readLine();
                requestMethod = reader.readLine();
                varyHeaders = new RawHeaders();
                int varyRequestHeaderLineCount = reader.readInt();
                for (int i = 0; i < varyRequestHeaderLineCount; i++) {
                    varyHeaders.addLine(reader.readLine());
                }
                responseHeaders = new RawHeaders();
                responseHeaders.setStatusLine(reader.readLine());
                int responseHeaderLineCount = reader.readInt();
                for (int i = 0; i < responseHeaderLineCount; i++) {
                    responseHeaders.addLine(reader.readLine());
                }
                cipherSuite = null;
                peerCertificates = null;
                localCertificates = null;
                
            } finally {
                in.close();
            }
        }
        public Entry(URI uri, RawHeaders varyHeaders, URLConnection httpConnection, String requestMethod) {
        	this.requestMethod = requestMethod;
            this.uri = uri.toString();
            this.varyHeaders = varyHeaders;
            this.responseHeaders = RawHeaders.fromMultimap(httpConnection.getHeaderFields());
            cipherSuite = null;
            peerCertificates = null;
            localCertificates = null;
            
        }
        public void writeTo(DiskLruCache.Editor editor) throws IOException {
            OutputStream out = editor.newOutputStream(ENTRY_METADATA);
            Writer writer = new BufferedWriter(new OutputStreamWriter(out, Util.UTF_8));
            writer.write(uri + '\n');
            writer.write(requestMethod + '\n');
            writer.write(Integer.toString(varyHeaders.length()) + '\n');
            for (int i = 0; i < varyHeaders.length(); i++) {
                writer.write(varyHeaders.getFieldName(i) + ": "
                        + varyHeaders.getValue(i) + '\n');
            }
            writer.write(responseHeaders.getStatusLine() + '\n');
            writer.write(Integer.toString(responseHeaders.length()) + '\n');
            for (int i = 0; i < responseHeaders.length(); i++) {
                writer.write(responseHeaders.getFieldName(i) + ": "
                        + responseHeaders.getValue(i) + '\n');
            }
            if (isHttps()) {
                writer.write('\n');
                writer.write(cipherSuite + '\n');
                writeCertArray(writer, peerCertificates);
                writeCertArray(writer, localCertificates);
            }
            writer.close();
        }
        private boolean isHttps() {
            return uri.startsWith("https://");
        }
        private Certificate[] readCertArray(StrictLineReader reader) throws IOException {
            int length = reader.readInt();
            if (length == -1) {
                return null;
            }
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                Certificate[] result = new Certificate[length];
                for (int i = 0; i < result.length; i++) {
                    String line = reader.readLine();
                    byte[] bytes = Base64.decode(line.getBytes(Util.US_ASCII));
                    result[i] = certificateFactory.generateCertificate(
                            new ByteArrayInputStream(bytes));
                }
                return result;
            } catch (CertificateException e) {
                throw new IOException(e);
            }
        }
        private void writeCertArray(Writer writer, Certificate[] certificates) throws IOException {
            if (certificates == null) {
                writer.write("-1\n");
                return;
            }
            try {
                writer.write(Integer.toString(certificates.length) + '\n');
                for (Certificate certificate : certificates) {
                    byte[] bytes = certificate.getEncoded();
                    String line = Base64.encode(bytes);
                    writer.write(line + '\n');
                }
            } catch (CertificateEncodingException e) {
                throw new IOException(e);
            }
        }
        public boolean matches(URI uri, String requestMethod,
                Map<String, List<String>> requestHeaders) {
            return this.uri.equals(uri.toString())
                    && this.requestMethod.equals(requestMethod);
        }
    }
    /**
     * Returns an input stream that reads the body of a snapshot, closing the
     * snapshot when the stream is closed.
     */
    private static InputStream newBodyInputStream(final DiskLruCache.Snapshot snapshot) {
        return new FilterInputStream(snapshot.getInputStream(ENTRY_BODY)) {
            @Override public void close() throws IOException {
                snapshot.close();
                super.close();
            }
        };
    }
    static class EntryCacheResponse extends CacheResponse {
        private final Entry entry;
        private final DiskLruCache.Snapshot snapshot;
        private final InputStream in;
        public EntryCacheResponse(Entry entry, DiskLruCache.Snapshot snapshot) {
            this.entry = entry;
            this.snapshot = snapshot;
            this.in = newBodyInputStream(snapshot);
        }
        @Override public Map<String, List<String>> getHeaders() {
            return entry.responseHeaders.toMultimap();
        }
        @Override public InputStream getBody() {
            return in;
        }
    }
    
    static class EntrySecureCacheResponse extends SecureCacheResponse {
        private final Entry entry;
        private final DiskLruCache.Snapshot snapshot;
        private final InputStream in;
        public EntrySecureCacheResponse(Entry entry, DiskLruCache.Snapshot snapshot) {
            this.entry = entry;
            this.snapshot = snapshot;
            this.in = newBodyInputStream(snapshot);
        }
        @Override public Map<String, List<String>> getHeaders() {
            return entry.responseHeaders.toMultimap();
        }
        @Override public InputStream getBody() {
            return in;
        }
        @Override public String getCipherSuite() {
            return entry.cipherSuite;
        }
        @Override public List<Certificate> getServerCertificateChain()
                throws SSLPeerUnverifiedException {
            if (entry.peerCertificates == null || entry.peerCertificates.length == 0) {
                throw new SSLPeerUnverifiedException(null);
            }
            return Arrays.asList(entry.peerCertificates.clone());
        }
        @Override public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
            if (entry.peerCertificates == null || entry.peerCertificates.length == 0) {
                throw new SSLPeerUnverifiedException(null);
            }
            return ((X509Certificate) entry.peerCertificates[0]).getSubjectX500Principal();
        }
        @Override public List<Certificate> getLocalCertificateChain() {
            if (entry.localCertificates == null || entry.localCertificates.length == 0) {
                return null;
            }
            return Arrays.asList(entry.localCertificates.clone());
        }
        @Override public Principal getLocalPrincipal() {
            if (entry.localCertificates == null || entry.localCertificates.length == 0) {
                return null;
            }
            return ((X509Certificate) entry.localCertificates[0]).getSubjectX500Principal();
        }
    }


}
