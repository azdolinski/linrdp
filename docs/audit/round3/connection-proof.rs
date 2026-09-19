use std::sync::{Arc,atomic::{AtomicUsize,Ordering}};
use std::time::Duration;
use ironrdp_server::{RdpServer,ConnectionHandler,PostConnectionAction,ServerError};
struct Handler(Arc<AtomicUsize>);
impl ConnectionHandler for Handler {
 fn on_disconnected(&mut self,_:std::net::SocketAddr,_:Duration,_:Option<&ServerError>)->PostConnectionAction {
  self.0.fetch_add(1,Ordering::SeqCst);PostConnectionAction::Continue
 }
}
fn main(){
 tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async{
  let called=Arc::new(AtomicUsize::new(0));
  let mut server=RdpServer::builder().with_addr(([127,0,0,1],0)).with_no_security().with_no_input().with_no_display()
   .with_connection_handler(Some(Box::new(Handler(called.clone())))).build();
  server.set_handshake_timeout(Some(Duration::from_millis(50)));
  let (_client,side)=tokio::io::duplex(64);
  let started=std::time::Instant::now();
  let answer=tokio::time::timeout(Duration::from_secs(2),server.run_connection(side)).await.expect("bounded");
  assert!(answer.is_err());
  println!("PASS F07: silent stream rejected after {:?}",started.elapsed());
  assert_eq!(called.load(Ordering::SeqCst),1);
  println!("PASS R04: run_connection invoked on_disconnected exactly once");
 });
}
