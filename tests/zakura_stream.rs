use cipherscan_indexer::db::grpc::{
    connect_block_stream_after_forks as connect_block_stream, proto,
};
use proto::indexer_server::{Indexer, IndexerServer};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
};
use tokio_stream::{wrappers::TcpListenerStream, Stream};
use tonic::{Request, Response, Status};

type Reply<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[derive(Clone)]
struct Node {
    next_tip: Arc<AtomicU8>,
    hash_len: Option<usize>,
    requests: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
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
        let tip = self.next_tip.fetch_add(1, Ordering::SeqCst);
        let messages = self.hash_len.map(|len| proto::BlockHashAndHeight {
            hash: vec![tip; len],
            height: u32::from(tip),
        });
        let messages = messages.into_iter().map(Ok::<_, Status>);
        Ok(Response::new(Box::pin(tokio_stream::iter(messages))))
    }
    async fn non_finalized_state_change(
        &self,
        request: Request<proto::NonFinalizedStateChangeRequest>,
    ) -> Result<Response<Self::NonFinalizedStateChangeStream>, Status> {
        self.requests
            .lock()
            .unwrap()
            .push(request.into_inner().chain_tip_hashes);
        Ok(Response::new(Box::pin(tokio_stream::iter([Ok(
            proto::BlockAndHash {
                receipt_order: None,
                hash: vec![9; 32],
                data: vec![42],
            },
        )]))))
    }
    async fn mempool_change(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<Self::MempoolChangeStream>, Status> {
        Ok(Response::new(Box::pin(tokio_stream::empty())))
    }
}

async fn server(hash_len: Option<usize>) -> (String, Node, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let node = Node {
        next_tip: Arc::new(AtomicU8::new(1)),
        hash_len,
        requests: Arc::new(Mutex::new(Vec::new())),
    };
    let service = node.clone();
    let handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(IndexerServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (url, node, handle)
}

#[tokio::test]
async fn reconnect_seeds_each_subscription_with_a_fresh_display_order_tip() {
    let (url, node, handle) = server(Some(32)).await;
    for _ in 0..2 {
        let mut stream = connect_block_stream(&url, vec![vec![7; 32]]).await.unwrap();
        assert_eq!(stream.message().await.unwrap().unwrap().data, vec![42]);
    }
    assert_eq!(
        *node.requests.lock().unwrap(),
        vec![
            vec![vec![7; 32], vec![1; 32]],
            vec![vec![7; 32], vec![2; 32]]
        ]
    );
    handle.abort();
}

#[tokio::test]
async fn malformed_tip_does_not_start_an_unbounded_subscription() {
    let (url, node, handle) = server(Some(31)).await;
    let error = connect_block_stream(&url, vec![vec![7; 32]])
        .await
        .err()
        .unwrap();
    assert!(error.contains("31 bytes"), "{error}");
    assert!(node.requests.lock().unwrap().is_empty());
    handle.abort();
}

#[tokio::test]
async fn closed_tip_stream_does_not_start_an_unbounded_subscription() {
    let (url, node, handle) = server(None).await;
    let error = connect_block_stream(&url, vec![vec![7; 32]])
        .await
        .err()
        .unwrap();
    assert!(error.contains("snapshot ended"), "{error}");
    assert!(node.requests.lock().unwrap().is_empty());
    handle.abort();
}
