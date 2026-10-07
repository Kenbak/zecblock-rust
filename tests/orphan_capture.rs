//! Synthetic trusted-node stream tests. The competing payload is a structural
//! fixture, not a consensus-valid mined fork; node validation is a separate gate.
use cipherscan_indexer::db::{grpc::proto, orphan_capture::run_capture};
use proto::indexer_server::{Indexer, IndexerServer};
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::{wrappers::TcpListenerStream, Stream};
use tonic::{Request, Response, Status};
use zakura_chain::{block::Block, serialization::ZcashDeserialize};

type Reply<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;
#[derive(Clone)]
struct Node {
    messages: Vec<proto::BlockAndHash>,
    requests: Arc<Mutex<Vec<proto::NonFinalizedStateChangeRequest>>>,
    canonical: Arc<Mutex<std::collections::HashMap<u64, String>>>,
}
#[tonic::async_trait]
impl Indexer for Node {
    type ChainTipChangeStream = Reply<proto::BlockHashAndHeight>;
    type NonFinalizedStateChangeStream = Reply<proto::BlockAndHash>;
    type MempoolChangeStream = Reply<proto::MempoolChangeMessage>;
    async fn chain_tip_change(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<Self::ChainTipChangeStream>, Status> {
        Ok(Response::new(Box::pin(tokio_stream::iter([Ok(
            proto::BlockHashAndHeight {
                hash: self.messages[0].hash.clone(),
                height: 419200,
            },
        )]))))
    }
    async fn non_finalized_state_change(
        &self,
        r: Request<proto::NonFinalizedStateChangeRequest>,
    ) -> Result<Response<Self::NonFinalizedStateChangeStream>, Status> {
        self.requests.lock().unwrap().push(r.into_inner());
        let mut response = Response::new(Box::pin(tokio_stream::iter(
            self.messages.clone().into_iter().map(Ok),
        )) as Self::NonFinalizedStateChangeStream);
        response
            .metadata_mut()
            .insert("x-zakura-receipt-session", "test-session".parse().unwrap());
        Ok(response)
    }
    async fn mempool_change(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<Self::MempoolChangeStream>, Status> {
        Ok(Response::new(Box::pin(tokio_stream::empty())))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn capture_replays_deduplicates_resumes_and_reclassifies_restored_branch_without_database() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/parser-blocks.json")).unwrap();
    let canonical_bytes = hex::decode(rows[1]["hex"].as_str().unwrap()).unwrap();
    let canonical_hash = rows[1]["hash"].as_str().unwrap().to_owned();
    let mut competing_bytes = hex::decode(rows[0]["hex"].as_str().unwrap()).unwrap();
    competing_bytes[108] ^= 1;
    let competing_hash = Block::zcash_deserialize(&mut std::io::Cursor::new(&competing_bytes))
        .unwrap()
        .hash()
        .to_string();
    let canonical = Arc::new(Mutex::new(std::collections::HashMap::from([
        (419199, rows[0]["hash"].as_str().unwrap().to_owned()),
        (419200, canonical_hash.clone()),
    ])));
    let node = Node {
        messages: vec![
            proto::BlockAndHash {
                hash: hex::decode(&canonical_hash).unwrap(),
                data: canonical_bytes,
                receipt_order: Some(1),
            },
            proto::BlockAndHash {
                hash: hex::decode(&competing_hash).unwrap(),
                data: competing_bytes,
                receipt_order: Some(2),
            },
        ],
        requests: Arc::default(),
        canonical: canonical.clone(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let service = node.clone();
    let grpc = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(IndexerServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    std::env::set_var(
        "ZEBRA_RPC_URL",
        format!("http://{}", listener.local_addr().unwrap()),
    );
    std::env::remove_var("ZEBRA_RPC_COOKIE_FILE");
    std::env::remove_var("ZEBRA_RPC_USER");
    std::env::remove_var("ZEBRA_RPC_PASS");
    // Any accidental production DB connection would fail; the capture code has no DB client.
    std::env::set_var(
        "DATABASE_URL",
        "postgres://127.0.0.1:1/should_never_connect",
    );
    let rpc_node = node.clone();
    let rpc = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let rpc_node = rpc_node.clone();
            tokio::spawn(async move {
                let mut bytes = vec![];
                let header_end = loop {
                    let mut buf = [0; 4096];
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..header_end]);
                let length = headers
                    .lines()
                    .find_map(|l| {
                        l.to_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|n| n.trim().parse::<usize>().ok())
                    })
                    .unwrap();
                while bytes.len() < header_end + length {
                    let mut buf = [0; 4096];
                    let n = socket.read(&mut buf).await.unwrap();
                    bytes.extend_from_slice(&buf[..n]);
                }
                let request: serde_json::Value =
                    serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "getblockchaininfo" => serde_json::json!({"chain":"main"}),
                    "getchaintips" => serde_json::json!([]),
                    "getblockhash" => serde_json::json!(
                        rpc_node.canonical.lock().unwrap()[&request["params"][0].as_u64().unwrap()]
                    ),
                    method => panic!("unexpected RPC {method}"),
                };
                let body = serde_json::to_vec(
                    &serde_json::json!({"result":result,"error":null,"id":"cipherscan"}),
                )
                .unwrap();
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            });
        }
    });
    let path = std::env::temp_dir().join(format!(
        "capture-stream-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let first = run_capture(
        &url,
        &path,
        "mainnet",
        Some(Duration::from_secs(3)),
        Some(1),
    )
    .await
    .unwrap();
    assert_eq!(first.new_blocks, 2);
    assert_eq!(first.total_records, 2);
    assert_eq!(first.canonical_at_check, 1);
    assert_eq!(first.non_canonical_at_check, 1);
    assert!(!first.database_accessed);
    assert!(first.reconnects >= 1);
    assert!(node.requests.lock().unwrap().len() >= 2);
    assert_eq!(
        node.requests.lock().unwrap()[1].receipt_session.as_deref(),
        Some("test-session")
    );
    assert!(node.requests.lock().unwrap()[1]
        .chain_tip_hashes
        .contains(&hex::decode(&canonical_hash).unwrap()));
    canonical
        .lock()
        .unwrap()
        .insert(419199, competing_hash.clone());
    let resumed = run_capture(&url, &path, "mainnet", Some(Duration::from_secs(1)), None)
        .await
        .unwrap();
    assert_eq!(resumed.new_blocks, 0);
    assert_eq!(resumed.total_records, 2);
    assert_eq!(resumed.canonical_at_check, 2);
    assert_eq!(resumed.non_canonical_at_check, 0);
    assert_eq!(
        std::fs::read_dir(&path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|f| f.path().extension().is_some_and(|e| e == "capture"))
            .count(),
        2
    );
    grpc.abort();
    rpc.abort();
    std::fs::remove_dir_all(path).unwrap();
}
