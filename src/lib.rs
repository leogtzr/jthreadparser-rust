const THREAD_INFORMATION_BEGINS: &'static str = r#"\""#;
const THREAD_NAME_RGX: &'static str = r#"^\"(.*)\".*prio=([0-9]+) tid=(\w*) nid=(\w*)\s\w*"#;
const STATE_RGX: &'static str = r#"\s+java.lang.Thread.State: (.*)"#;
const LOCKED_RGX: &'static str = r#"\s*\- locked\s*<(.*)>\s*\(a\s(.*)\)"#;
const PARKINGORWAITING_RGX: &'static str = r#"\s*\- (?:waiting on|parking to wait for)\s*<(.*)>\s*\(a\s(.*)\)"#;
const STACKTRACE_RGX: &'static str = r#"^\s+(at|\-\s).*\)$"#;
const STACKTRACE_RGX_METHOD_NAME: &'static str = r#"at\s+(.*)$"#;
const THREADNAME_RGX_GROUP_INDEX: i32 = 1;
const THREADPRIORITY_RGX_GROUP_INDEX: i32 = 2;
const THREADID_RGX_GROUP_INDEX: i32 = 3;
const THREADNATIVE_ID_RGX_GROUP_INDEX: i32 = 4;

struct ThreadInfo {
	name: String, 
    id: String, 
    native_id: String, 
    priority: String, 
    state: String, 
    stack_trace: String,
	daemon: bool,
}

impl ToString for ThreadInfo {
    fn to_string(&self) -> String {
        if self.daemon {
		    format!("Thread Id: '{}' (daemon), Name: '{}', State: '{}'", self.id, self.name, self.state)
	    } else {
            format!("Thread Id: '{}', Name: '{}', State: '{}'", self.id, self.name, self.state)
        }
    }
}

struct Locked {
	lock_id: String, 
    locked_object_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREAD_INFO: &'static str = r#""Attach Listener" daemon prio=10 tid=0x00002aaab74c5000 nid=0x2ea5 waiting on condition [0x0000000000000000]`
	threadStateLine = `   java.lang.Thread.State: TIMED_WAITING (parking)`

	threadInformation = `"HDScanner" prio=10 tid=0x00002aaaebf6e800 nid=0x4367 runnable [0x00000000451cf000]
   java.lang.Thread.State: RUNNABLE
	at java.io.UnixFileSystem.getBooleanAttributes0(Native Method)
	at java.io.UnixFileSystem.getBooleanAttributes(UnixFileSystem.java:228)
	at java.io.File.isHidden(File.java:804)

   Locked ownable synchronizers:
	- <0x00000007500b7250> (a java.util.concurrent.locks.ReentrantLock$NonfairSync)
	"#;

	const DAEMON_THREAD_INFORMATION: &'static str = r#""Attach Listener" #6085 daemon prio=9 os_prio=0 tid=0x00007f90d0106000 nid=0x18a1 runnable [0x0000000000000000]
	java.lang.Thread.State: RUNNABLE
 
	Locked ownable synchronizers:
	 - None"#;

	const THREAD_INFO_WITHLOCKS: &'static str = r#""default task-23" #349 prio=5 os_prio=0 tid=0x00007f8fe400c800 nid=0x72fa waiting for monitor entry [0x00007f8f7228e000]
	java.lang.Thread.State: BLOCKED (on object monitor)
	 at java.security.Provider.getService(Provider.java:1039)
	 - locked <0x0000000682e5f948> (a sun.security.provider.Sun)
	 at sun.security.jca.ProviderList.getService(ProviderList.java:332)
	 at sun.security.jca.GetInstance.getInstance(GetInstance.java:157)
	 at java.security.Security.getImpl(Security.java:695)
	 at java.security.MessageDigest.getInstance(MessageDigest.java:167)
	 at sun.security.rsa.RSASignature.<init>(RSASignature.java:79)
	 at sun.security.rsa.RSASignature$SHA512withRSA.<init>(RSASignature.java:305)
	 at sun.reflect.NativeConstructorAccessorImpl.newInstance0(Native Method)
	 at sun.reflect.NativeConstructorAccessorImpl.newInstance(NativeConstructorAccessorImpl.java:62)
	 at sun.reflect.DelegatingConstructorAccessorImpl.newInstance(DelegatingConstructorAccessorImpl.java:45)
	 at java.lang.reflect.Constructor.newInstance(Constructor.java:423)
	 at java.security.Provider$Service.newInstance(Provider.java:1595)
	 at java.security.Signature$Delegate.newInstance(Signature.java:1020)
	 at java.security.Signature$Delegate.chooseProvider(Signature.java:1114)
	 - locked <0x00000007bc531138> (a java.lang.Object)
	 at java.security.Signature$Delegate.engineInitSign(Signature.java:1188)
	 at java.security.Signature.initSign(Signature.java:553)
	 at sun.security.ssl.HandshakeMessage$ECDH_ServerKeyExchange.<init>(HandshakeMessage.java:1031)
	 at sun.security.ssl.ServerHandshaker.clientHello(ServerHandshaker.java:971)
	 at sun.security.ssl.ServerHandshaker.processMessage(ServerHandshaker.java:228)
	 at sun.security.ssl.Handshaker.processLoop(Handshaker.java:1052)
	 at sun.security.ssl.Handshaker$1.run(Handshaker.java:992)
	 at sun.security.ssl.Handshaker$1.run(Handshaker.java:989)
	 at java.security.AccessController.doPrivileged(Native Method)
	 at sun.security.ssl.Handshaker$DelegatedTask.run(Handshaker.java:1467)
	 - locked <0x00000007bbbac500> (a sun.security.ssl.SSLEngineImpl)
	 at io.undertow.protocols.ssl.SslConduit$5.run(SslConduit.java:1021)
	 at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
	 at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
	 at java.lang.Thread.run(Thread.java:748)
 
	Locked ownable synchronizers:
	 - <0x00000006a43d5c08> (a java.util.concurrent.ThreadPoolExecutor$Worker)
 "#;
	
    const THREAD_DUMP_SAMPLE: &'static str = r#"2017-06-02 19:02:52
Full thread dump Java HotSpot(TM) 64-Bit Server VM (20.141-b32 mixed mode):

"Attach Listener" daemon prio=10 tid=0x00002aaab74c5000 nid=0x2ea5 waiting on condition [0x0000000000000000]
	java.lang.Thread.State: RUNNABLE

	Locked ownable synchronizers:
	- None

"RMI TCP Connection(idle)" daemon prio=10 tid=0x00002aaac69b1800 nid=0x2dec waiting on condition [0x0000000051388000]
	java.lang.Thread.State: TIMED_WAITING (parking)
	at sun.misc.Unsafe.park(Native Method)
	- parking to wait for  <0x0000000740c99708> (a java.util.concurrent.SynchronousQueue$TransferStack)
	at java.util.concurrent.locks.LockSupport.parkNanos(LockSupport.java:196)
	at java.util.concurrent.SynchronousQueue$TransferStack.awaitFulfill(SynchronousQueue.java:424)
	at java.lang.Thread.run(Thread.java:682)

	Locked ownable synchronizers:
	- None

"RMI TCP Connection(idle)" daemon prio=10 tid=0x00002aaad5029000 nid=0x2bf8 waiting on condition [0x0000000051287000]
	java.lang.Thread.State: TIMED_WAITING (parking)
	at sun.misc.Unsafe.park(Native Method)
	- parking to wait for  <0x0000000740c99708> (a java.util.concurrent.SynchronousQueue$TransferStack)
	at java.util.concurrent.locks.LockSupport.parkNanos(LockSupport.java:196)
	at java.util.concurrent.SynchronousQueue$TransferStack.awaitFulfill(SynchronousQueue.java:424)
	at java.lang.Thread.run(Thread.java:682)

	Locked ownable synchronizers:
	- None"#;

    #[test]
    fn should_tag_correctly_daemon_thread() {
        let expected_thread_string_info: String = String::from("Thread Id: '0x00007f90d0106000' (daemon), Name: 'Attach Listener', State: 'RUNNABLE'");

        let mut th = ThreadInfo{
            id: String::from("0x00007f90d0106000")
            , name: String::from("Attach Listener")
            , state: String::from("RUNNABLE")
            , daemon: true
            , native_id: String::from("")
            , priority: String::from(""),
            stack_trace: String::from(""),
        };
        assert_eq!(th.to_string(), expected_thread_string_info);

        th.daemon = false;

        let expected_thread_string_info = "Thread Id: '0x00007f90d0106000', Name: 'Attach Listener', State: 'RUNNABLE'";
        assert_eq!(th.to_string(), expected_thread_string_info);
    }
}