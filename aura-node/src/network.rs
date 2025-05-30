use libp2p::{
    gossipsub::{self, MessageAuthenticity},
    identify,
    kad::{self, store::MemoryStore},
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp,
    yamux,
    PeerId, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use bincode::{Encode, Decode};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tracing::{info, warn};
use crate::config::NetworkConfig;

#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct AuraNetworkBehaviour {
    gossipsub: gossipsub::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
}

pub struct NetworkManager {
    swarm: libp2p::Swarm<AuraNetworkBehaviour>,
    topics: NetworkTopics,
}

pub struct NetworkTopics {
    pub blocks: gossipsub::IdentTopic,
    pub transactions: gossipsub::IdentTopic,
    pub did_updates: gossipsub::IdentTopic,
}

impl NetworkTopics {
    fn new() -> Self {
        Self {
            blocks: gossipsub::IdentTopic::new("aura/blocks/1.0.0"),
            transactions: gossipsub::IdentTopic::new("aura/transactions/1.0.0"),
            did_updates: gossipsub::IdentTopic::new("aura/did-updates/1.0.0"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum NetworkMessage {
    NewBlock(Vec<u8>),
    NewTransaction(Vec<u8>),
    DidUpdate(Vec<u8>),
}

impl NetworkManager {
    pub async fn new(config: NetworkConfig) -> anyhow::Result<Self> {
        // Create a random peer ID
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        
        info!("Local peer ID: {}", local_peer_id);
        
        // Transport will be created by SwarmBuilder
        
        // Create Gossipsub
        let message_id_fn = |message: &gossipsub::Message| {
            let mut hasher = DefaultHasher::new();
            message.data.hash(&mut hasher);
            gossipsub::MessageId::from(hasher.finish().to_string())
        };
        
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build gossipsub config: {}", e))?;
        
        let mut gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        ).map_err(|e| anyhow::anyhow!("Failed to create gossipsub: {}", e))?;
        
        // Create topics and subscribe
        let topics = NetworkTopics::new();
        gossipsub.subscribe(&topics.blocks)
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to blocks topic: {}", e))?;
        gossipsub.subscribe(&topics.transactions)
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to transactions topic: {}", e))?;
        gossipsub.subscribe(&topics.did_updates)
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to did-updates topic: {}", e))?;
        
        // Create Kademlia
        let kademlia = kad::Behaviour::new(local_peer_id, MemoryStore::new(local_peer_id));
        
        // Create Identify
        let identify = identify::Behaviour::new(identify::Config::new(
            "/aura/1.0.0".to_string(),
            local_key.public(),
        ));
        
        // Create the network behaviour
        let behaviour = AuraNetworkBehaviour {
            gossipsub,
            kademlia,
            identify,
        };
        
        // Create swarm
        let mut swarm = SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
            .map_err(|e| anyhow::anyhow!("Failed to configure TCP transport: {:?}", e))?
            .with_behaviour(|_key| Ok(behaviour))
            .map_err(|e| anyhow::anyhow!("Failed to configure behaviour: {:?}", e))?
            .build();
        
        // Listen on configured addresses
        for addr in &config.listen_addresses {
            match addr.parse() {
                Ok(multiaddr) => {
                    swarm.listen_on(multiaddr)
                        .map_err(|e| anyhow::anyhow!("Failed to listen on address: {}", e))?;
                    info!("Listening on {}", addr);
                }
                Err(e) => {
                    warn!("Failed to parse listen address {}: {}", addr, e);
                }
            }
        }
        
        // Connect to bootstrap nodes
        for bootstrap in &config.bootstrap_nodes {
            if let Ok(multiaddr) = bootstrap.parse::<libp2p::Multiaddr>() {
                match swarm.dial(multiaddr) {
                    Ok(_) => info!("Dialing bootstrap node: {}", bootstrap),
                    Err(e) => warn!("Failed to dial bootstrap node {}: {}", bootstrap, e),
                }
            }
        }
        
        Ok(Self { swarm, topics })
    }
    
    pub async fn broadcast_block(&mut self, block_data: Vec<u8>) -> anyhow::Result<()> {
        let message = NetworkMessage::NewBlock(block_data);
        let data = bincode::encode_to_vec(&message, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?;
        
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topics.blocks.clone(), data)
            .map_err(|e| anyhow::anyhow!("Failed to publish block: {:?}", e))?;
        
        Ok(())
    }
    
    pub async fn broadcast_transaction(&mut self, tx_data: Vec<u8>) -> anyhow::Result<()> {
        let message = NetworkMessage::NewTransaction(tx_data);
        let data = bincode::encode_to_vec(&message, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?;
        
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topics.transactions.clone(), data)
            .map_err(|e| anyhow::anyhow!("Failed to publish transaction: {:?}", e))?;
        
        Ok(())
    }
    
    pub async fn broadcast_did_update(&mut self, did_data: Vec<u8>) -> anyhow::Result<()> {
        let message = NetworkMessage::DidUpdate(did_data);
        let data = bincode::encode_to_vec(&message, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?;
        
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.topics.did_updates.clone(), data)
            .map_err(|e| anyhow::anyhow!("Failed to publish DID update: {:?}", e))?;
        
        Ok(())
    }
    
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            match self.swarm.next().await {
                Some(SwarmEvent::Behaviour(event)) => {
                    self.handle_behaviour_event(event).await;
                }
                Some(SwarmEvent::NewListenAddr { address, .. }) => {
                    info!("Listening on: {}", address);
                }
                Some(SwarmEvent::ConnectionEstablished { peer_id, connection_id: _, .. }) => {
                    info!("Connected to peer: {}", peer_id);
                }
                Some(SwarmEvent::ConnectionClosed { peer_id, connection_id: _, .. }) => {
                    info!("Disconnected from peer: {}", peer_id);
                }
                _ => {}
            }
        }
    }
    
    async fn handle_behaviour_event(&mut self, event: AuraNetworkBehaviourEvent) {
        match event {
            AuraNetworkBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source: _,
                message_id: _,
                message,
            }) => {
                let topic = message.topic.clone();
                
                match bincode::decode_from_slice::<NetworkMessage, _>(&message.data, bincode::config::standard())
                    .map(|(msg, _)| msg) {
                    Ok(network_msg) => {
                        if topic == self.topics.blocks.hash() {
                            self.handle_new_block(network_msg).await;
                        } else if topic == self.topics.transactions.hash() {
                            self.handle_new_transaction(network_msg).await;
                        } else if topic == self.topics.did_updates.hash() {
                            self.handle_did_update(network_msg).await;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to deserialize message: {}", e);
                    }
                }
            }
            AuraNetworkBehaviourEvent::Identify(identify::Event::Received { peer_id, info, connection_id: _ }) => {
                info!("Identified peer {}: {:?}", peer_id, info.protocol_version);
            }
            _ => {}
        }
    }
    
    async fn handle_new_block(&mut self, message: NetworkMessage) {
        if let NetworkMessage::NewBlock(data) = message {
            info!("Received new block, size: {} bytes", data.len());
            // TODO: Process the block
        }
    }
    
    async fn handle_new_transaction(&mut self, message: NetworkMessage) {
        if let NetworkMessage::NewTransaction(data) = message {
            info!("Received new transaction, size: {} bytes", data.len());
            // TODO: Add to transaction pool
        }
    }
    
    async fn handle_did_update(&mut self, message: NetworkMessage) {
        if let NetworkMessage::DidUpdate(data) = message {
            info!("Received DID update, size: {} bytes", data.len());
            // TODO: Process DID update
        }
    }
}

use futures::StreamExt;