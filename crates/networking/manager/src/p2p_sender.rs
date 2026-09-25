use anyhow::anyhow;
use libp2p::{
    PeerId,
    gossipsub::{MessageAcceptance, MessageId},
    swarm::ConnectionId,
};
use ream_p2p::network::beacon::channel::{GossipMessage, P2PMessage, P2PResponse};
use ream_req_resp::{
    beacon::messages::BeaconResponseMessage, error::ReqRespError, handler::RespMessage,
    messages::ResponseMessage,
};
use tokio::sync::mpsc;
use tracing::warn;

#[derive(Clone)]
pub struct P2PSender(pub mpsc::UnboundedSender<P2PMessage>);

impl P2PSender {
    pub async fn subscribe(
        &self,
        topic: ream_p2p::gossipsub::beacon::topics::GossipTopic,
    ) -> anyhow::Result<()> {
        let (response, receiver) = tokio::sync::oneshot::channel();
        self.0
            .send(P2PMessage::Subscribe { topic, response })
            .map_err(|_| anyhow!("P2P service is unavailable"))?;
        let subscribed =
            tokio::time::timeout(std::time::Duration::from_secs(5), receiver).await??;
        anyhow::ensure!(subscribed, "Failed to subscribe to gossip topic");
        Ok(())
    }

    pub fn send_gossip(&self, message: GossipMessage) {
        if let Err(err) = self.0.send(P2PMessage::Gossip(message)) {
            warn!("Failed to send gossip message: {err}");
        }
    }

    pub fn report_gossip_validation(
        &self,
        message_id: MessageId,
        propagation_source: PeerId,
        acceptance: MessageAcceptance,
    ) {
        if let Err(err) = self.0.send(P2PMessage::ReportGossipValidation {
            message_id,
            propagation_source,
            acceptance,
        }) {
            warn!("Failed to send gossip validation report: {err}");
        }
    }

    pub fn send_response(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        message: BeaconResponseMessage,
    ) {
        if let Err(err) = self.0.send(P2PMessage::Response(P2PResponse {
            peer_id,
            connection_id,
            stream_id,
            message: Box::new(RespMessage::Response(Box::new(ResponseMessage::Beacon(
                message.into(),
            )))),
        })) {
            warn!("Failed to send P2P response: {err}");
        }
    }

    pub fn send_end_of_stream_response(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
    ) {
        if let Err(err) = self.0.send(P2PMessage::Response(P2PResponse {
            peer_id,
            connection_id,
            stream_id,
            message: Box::new(RespMessage::EndOfStream),
        })) {
            warn!("Failed to send end of stream response: {err}");
        }
    }

    pub fn send_error_response(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        error: &str,
    ) {
        if let Err(err) = self.0.send(P2PMessage::Response(P2PResponse {
            peer_id,
            connection_id,
            stream_id,
            message: Box::new(RespMessage::Error(ReqRespError::Anyhow(anyhow!(
                error.to_string()
            )))),
        })) {
            warn!("Failed to send error response: {err}");
        }
    }

    pub fn send_invalid_request(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        stream_id: u64,
        error: &str,
    ) {
        if let Err(err) = self.0.send(P2PMessage::Response(P2PResponse {
            peer_id,
            connection_id,
            stream_id,
            message: Box::new(RespMessage::Error(ReqRespError::InvalidData(
                error.to_string(),
            ))),
        })) {
            warn!("Failed to send invalid-request response: {err}");
        }
    }
}

#[cfg(test)]
mod subscription_tests {
    use super::*;
    use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};

    #[tokio::test]
    async fn subscription_waits_for_network_ack_and_reports_failure() {
        let topic = GossipTopic {
            fork: Default::default(),
            kind: GossipTopicKind::SyncCommittee(3),
        };
        for success in [true, false] {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let sender = P2PSender(tx);
            let network = tokio::spawn(async move {
                match rx.recv().await.unwrap() {
                    P2PMessage::Subscribe {
                        topic: actual,
                        response,
                    } => {
                        assert_eq!(actual, topic);
                        response.send(success).unwrap();
                    }
                    _ => panic!("expected subscription"),
                }
            });
            assert_eq!(sender.subscribe(topic).await.is_ok(), success);
            network.await.unwrap();
        }
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        assert!(P2PSender(tx).subscribe(topic).await.is_err());
    }
}
