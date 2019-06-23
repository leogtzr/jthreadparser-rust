extern crate regex;
use regex::Regex;

use std::io::{BufRead};
use std::io::BufReader;
use std::fs::File;
use stringreader::StringReader;
use std::collections::HashMap;
use std::hash::Hasher;
use std::hash::Hash;

const THREAD_INFORMATION_BEGINS: &'static str = r#"""#;
const THREAD_NAME_RGX: &'static str = r#"^"(.*)".*prio=([0-9]+) tid=(\w*) nid=(\w*)\s\w*"#;
const STATE_RGX: &'static str = r#"\s+java.lang.Thread.State: (.*)"#;
const THREAD_STATE: &'static str = "java.lang.Thread.State: ";
const LOCKED_RGX: &'static str = r#"\s*\- locked\s*<(.*)>\s*\(a\s(.*)\)"#;
const PARKINGORWAITING_RGX: &'static str = r#"\s*\- (?:waiting on|parking to wait for)\s*<(.*)>\s*\(a\s(.*)\)"#;
const STACKTRACE_RGX: &'static str = r#"^\s+(at|\-\s).*\)$"#;
const STACKTRACE_RGX_METHOD_NAME: &'static str = r#"at\s+(.*)$"#;
const THREADNAME_RGX_GROUP_INDEX: usize = 1;
const THREADPRIORITY_RGX_GROUP_INDEX: usize = 2;
const THREADID_RGX_GROUP_INDEX: usize = 3;
const THREADNATIVE_ID_RGX_GROUP_INDEX: usize = 4;

#[derive(Debug, Clone)]
pub struct ThreadInfo {
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

impl ThreadInfo {
	fn empty() -> ThreadInfo {
		ThreadInfo {
			name: String::from(""),
			id: String::from(""), 
			native_id: String::from(""), 
			priority: String::from(""), 
			state: String::from(""), 
			stack_trace: String::from(""),
			daemon: false,
		}
	}
}

#[derive(Debug)]
pub struct Locked {
	lock_id: String, 
    locked_object_name: String,
}

impl PartialEq for ThreadInfo {
	fn eq(&self, other: &Self) -> bool {
        (self.name == other.name) 
		&& (self.id == other.id) 
		&& (self.native_id == other.native_id)
		&& (self.priority == other.priority)
		&& (self.state == other.state)
		&& (self.daemon == other.daemon)
    }
}

impl Eq for ThreadInfo {}

impl PartialEq for Locked {
	fn eq(&self, other: &Self) -> bool {
		(self.lock_id == other.lock_id) && (self.locked_object_name == other.locked_object_name)
	}
}

impl Hash for ThreadInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
		self.name.hash(state);
		self.id.hash(state);
		self.native_id.hash(state);
		self.priority.hash(state);
		self.state.hash(state);
		self.daemon.hash(state);

    }
}

fn extract_thread_state(line: String) -> String {
	let state_tokens = line.split_whitespace().collect::<Vec<&str>>();
	state_tokens[1].trim().to_string()
}

pub fn parse_from<R: BufRead>(r: &mut R, threads: &mut Vec<ThreadInfo>) {
	let lines: Vec<_> = r.lines().map(|line| line.unwrap()).collect();

	let mut rg = Regex::new(THREAD_NAME_RGX).unwrap();

	for mut line_index in 0..lines.len() {
		let line = lines.get(line_index).unwrap();
		if line.starts_with(THREAD_INFORMATION_BEGINS) {
			let mut ti = extract_thread_info_from_line(line.clone(), &mut rg);
			line_index += 1;
			let line = lines.get(line_index).unwrap();
			if line.contains(THREAD_STATE) {
				ti.state = extract_thread_state(line.to_string());
				line_index += 1;
				
				let mut stacktrace = String::new();
				let mut line = lines.get(line_index).unwrap().trim();
				
				if !line.is_empty() {			// Stacktrace ...
					loop {
						if !line.is_empty() {
							stacktrace.push_str(line);
							stacktrace.push_str("\n");
							ti.stack_trace = stacktrace.clone();
						} else {
							break;
						}

						line_index += 1;
						if line_index >= lines.len() {
							break;
						}
						line = lines.get(line_index).unwrap().trim();
					}
				}

			}
			threads.push(ti);
		}
	}
}

fn extract_thread_info_from_line(line: String, rg: &mut Regex) -> ThreadInfo {
	let mut ti = ThreadInfo::empty();
	if rg.is_match(&line) {
		if line.contains(" daemon ") {
			ti.daemon = true
		}
		match rg.captures(&line) {
			Some(group) => {
				if let Some(group_index) = group.get(THREADNAME_RGX_GROUP_INDEX) {
					ti.name = group_index.as_str().to_string();
				}

				if let Some(group_index) = group.get(THREADPRIORITY_RGX_GROUP_INDEX) {
					ti.priority = group_index.as_str().to_string();
				}

				if let Some(group_index) = group.get(THREADID_RGX_GROUP_INDEX) {
					ti.id = group_index.as_str().to_string();
				}

				if let Some(group_index) = group.get(THREADNATIVE_ID_RGX_GROUP_INDEX) {
					ti.native_id = group_index.as_str().to_string();
				}
			},
			None => {},
		}
	}
	ti
}

pub fn holds(threads: &Vec<ThreadInfo>) -> HashMap<ThreadInfo, Vec<Locked>> {
	let mut holds = HashMap::new();
	let re = Regex::new(LOCKED_RGX).unwrap();

	for th in threads {
		if th.stack_trace.is_empty() {
			continue;
		}
		for stack_line in th.stack_trace.split("\n") {
			if re.is_match(&stack_line) {
				match re.captures(&stack_line) {
					Some(group) => {
						let x = holds.entry(th.clone()).or_insert(Vec::new());
						x.push(Locked{
							lock_id: group.get(1).unwrap().as_str().to_string(),
							locked_object_name: group.get(2).unwrap().as_str().to_string(),
						});						
					},
					None => {},
				}

			}
		}
	}
	holds
}

pub fn holds_for_thread(th: &ThreadInfo) -> Vec<Locked> {
	if !th.stack_trace.contains(" locked ") {
		return Vec::new();
	}
	let mut holds = Vec::new();
	let re = Regex::new(LOCKED_RGX).unwrap();
	for stack_line in th.stack_trace.split("\n") {
		if re.is_match(&stack_line) {
			match re.captures(&stack_line) {
				Some(group) => {
					holds.push(Locked{
						lock_id: group.get(1).unwrap().as_str().to_string(),
						locked_object_name: group.get(2).unwrap().as_str().to_string(),
					});						
				},
				None => {},
			}

		}
	}
	holds
}

fn unique_stack_trace(thread_stack_trace: Vec<&str>) -> Vec<String> {
	let mut u: Vec<String> = Vec::new();
	let mut m: HashMap<String, bool> = HashMap::new(); // make(map[string]bool)

	for line in thread_stack_trace {
		match m.get(line) {
			Some(_) => {},
			None => {
				m.insert(line.to_owned(), true);
				u.push(line.to_string());
			}
		}
	}
	u
}

fn extract_java_method_name_from_stack_trace_line(stacktrace_line: String, rg: &mut Regex) -> String {
	let mut method_name = String::from("");
	if rg.is_match(&stacktrace_line) {
		let fields = stacktrace_line.split_whitespace().collect::<Vec<&str>>();
		let fields = &fields[1..];
		for field in fields {
			method_name.push_str(field);
			method_name.push_str(" ");
		}
	}
	method_name.trim().to_string()
}

pub fn most_used_methods(threads: &Vec<ThreadInfo>) -> HashMap<String, i32> {

	let mut most_used_methods_general = HashMap::new();
	let mut rg = Regex::new(STACKTRACE_RGX_METHOD_NAME).unwrap();
	for th in threads {
		let stacktrace_lines = unique_stack_trace(th.stack_trace.split("\n").collect::<Vec<&str>>());

		for stacktrace_line in stacktrace_lines {
			if stacktrace_line.is_empty() {
				continue
			}
			let stacktrace_line = extract_java_method_name_from_stack_trace_line(stacktrace_line, &mut rg);
			let count = most_used_methods_general.entry(stacktrace_line).or_insert(0);
			*count += 1;
		}
	}
	most_used_methods_general
}

pub fn identical_stack_trace(threads: &Vec<ThreadInfo>) -> HashMap<String, i32> {
	let mut indentical_stack_trace = HashMap::new();
	for th in threads {
		let th_stack = th.stack_trace.trim();
		let count = indentical_stack_trace.entry(th_stack.to_string()).or_insert(0);
        *count += 1;
	}
	indentical_stack_trace
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREAD_INFO: &'static str = r#""Attach Listener" daemon prio=10 tid=0x00002aaab74c5000 nid=0x2ea5 waiting on condition [0x0000000000000000]"#;
	const THREAD_STATE_LINE: &'static str = r#"   java.lang.Thread.State: TIMED_WAITING (parking)"#;

	const THREAD_INFORMATION: &'static str = r#""HDScanner" prio=10 tid=0x00002aaaebf6e800 nid=0x4367 runnable [0x00000000451cf000]
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

	#[test]
	fn test_extract_thread_state() {
		const EXPECTED_STATE: &'static str = "TIMED_WAITING";
		let state = extract_thread_state(String::from(THREAD_STATE_LINE));
		assert_eq!(state, EXPECTED_STATE);
	}

	#[test]
	fn test_thread_info() {
		let mut rg = Regex::new(THREAD_NAME_RGX).unwrap();
		let th = extract_thread_info_from_line(THREAD_INFO.to_string(), &mut rg);
		assert_eq!(th.name, "Attach Listener");
		assert_eq!(th.id, "0x00002aaab74c5000");
		assert_eq!(th.native_id, "0x2ea5");
	}

	#[test]
	fn test_holds() {
		let expected_number_of_threads = 1;
		let expected_locks = vec![
				Locked { lock_id: String::from("0x0000000682e5f948"), locked_object_name: String::from("sun.security.provider.Sun") },
                Locked { lock_id: String::from("0x00000007bc531138"), locked_object_name: String::from("java.lang.Object") },
                Locked { lock_id: String::from("0x00000007bbbac500"), locked_object_name: String::from("sun.security.ssl.SSLEngineImpl") }
		];
		let expected_thread_id_with_locks = String::from("0x00007f8fe400c800");

		let streader = StringReader::new(THREAD_INFO_WITHLOCKS);
		let mut br = BufReader::new(streader);
    	let mut threads: Vec<ThreadInfo> = vec![];

		parse_from(&mut br, &mut threads);

		let holds = holds(&threads);
		for (key, val) in &holds {
			assert_eq!(expected_thread_id_with_locks, key.id);
			assert_eq!(expected_locks.len(), val.len());
			for lock_index in 0..expected_locks.len() {
				assert_eq!(expected_locks[lock_index], val[lock_index]);
			}
		}


		assert_eq!(holds.len(), expected_number_of_threads);
	}

	#[test]
	fn test_holds_for_thread() {
		let streader = StringReader::new(THREAD_INFO_WITHLOCKS);
		let mut br = BufReader::new(streader);
    	let mut threads: Vec<ThreadInfo> = vec![];
		let expected_number_of_locks_in_thread_with_lock_info = 3;

		let expected_locks = vec![
				Locked { lock_id: String::from("0x0000000682e5f948"), locked_object_name: String::from("sun.security.provider.Sun") },
                Locked { lock_id: String::from("0x00000007bc531138"), locked_object_name: String::from("java.lang.Object") },
                Locked { lock_id: String::from("0x00000007bbbac500"), locked_object_name: String::from("sun.security.ssl.SSLEngineImpl") }
		];

		parse_from(&mut br, &mut threads);

		for thread in threads {
			let holds = holds_for_thread(&thread);
			assert_eq!(holds.len(), expected_number_of_locks_in_thread_with_lock_info);

			for lock_index in 0..expected_locks.len() {
				assert_eq!(expected_locks[lock_index], holds[lock_index]);
			}
		}
	}

	#[test]
	fn test_identical_strack_trace() {
		let expected_number_of_threads_with_identical_stack_trace = 20;
		let stacktrace = r#"at sun.misc.Unsafe.park(Native Method)
- parking to wait for  <0x0000000750785368> (a java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject)
at java.util.concurrent.locks.LockSupport.park(LockSupport.java:156)
at java.util.concurrent.locks.AbstractQueuedSynchronizer$ConditionObject.await(AbstractQueuedSynchronizer.java:1987)
at java.util.concurrent.LinkedBlockingQueue.take(LinkedBlockingQueue.java:399)
at java.util.concurrent.ThreadPoolExecutor.getTask(ThreadPoolExecutor.java:957)
at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:917)
at java.lang.Thread.run(Thread.java:682)"#;

		let f = File::open("tdump.sample").unwrap();
		let mut br = BufReader::new(f);
    	let mut threads: Vec<ThreadInfo> = vec![];
		parse_from(&mut br, &mut threads);

		let identical_stack_trace = identical_stack_trace(&threads);
		assert_eq!(identical_stack_trace[stacktrace], expected_number_of_threads_with_identical_stack_trace);
	}

	#[test]
	fn test_top_methods_in_threads() {
		let f = File::open("tdump.sample").unwrap();
		let mut br = BufReader::new(f);
    	let mut threads: Vec<ThreadInfo> = vec![];
		parse_from(&mut br, &mut threads);

		let most_used_methods = most_used_methods(&threads);

		let java_method_name = "java.lang.Object.wait(Native Method)";

		let expected_number_of_threads_with_method_name = 82;

		match most_used_methods.get(java_method_name) {
			Some(count) => {
				assert_eq!(*count, expected_number_of_threads_with_method_name);
			},
			None => {
				panic!("key not found in map");
			}
		}
	}

}