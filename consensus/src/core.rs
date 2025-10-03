use std::collections::{HashMap, HashSet};

use crate::aggregator::Aggregator;
use crate::config::{Committee, Parameters, Stake};
use crate::error::{ConsensusError, ConsensusResult};
use crate::filter::FilterInput;
use crate::mempool::MempoolDriver;
use crate::messages::{ABAOutput, ABAVal, Block, EchoVote, RBCProof, RandomnessShare, ReadyVote};
use crate::synchronizer::Synchronizer;
use async_recursion::async_recursion;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use store::Store;
use threshold_crypto::PublicKeySet;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};
#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub type SeqNumber = u64; // For both round and view
pub type HeightNumber = u8; // height={1,2} in fallback chain, height=0 for sync block

pub const RBC_ECHO: u8 = 0;
pub const RBC_READY: u8 = 1;

pub const VAL_PHASE: u8 = 0;
pub const MUX_PHASE: u8 = 1;

pub const OPT: u8 = 1;
pub const PES: u8 = 0;

#[derive(Serialize, Deserialize, Debug)]
pub enum ConsensusMessage {
    RBCValMsg(Block),
    RBCEchoMsg(EchoVote),
    RBCReadyMsg(ReadyVote),
    LeaderShareMsg(RandomnessShare),
    ABAValMsg(ABAVal),
    ABAMuxMsg(ABAVal),
    ABACoinShareMsg(RandomnessShare),
    ABAOutputMsg(ABAOutput),
    LoopBackMsg(SeqNumber, SeqNumber),
    SyncRequestMsg(SeqNumber, SeqNumber, PublicKey),
    SyncReplyMsg(Block),
}

pub struct Core {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    store: Store,
    signature_service: SignatureService,
    pk_set: PublicKeySet,
    mempool_driver: MempoolDriver,
    synchronizer: Synchronizer,
    _tx_core: Sender<ConsensusMessage>,
    rx_core: Receiver<ConsensusMessage>,
    network_filter: Sender<FilterInput>,
    _commit_channel: Sender<Block>,
    epoch: SeqNumber,
    height: SeqNumber,
    aggregator: Aggregator,
    rbc_proofs: HashMap<(SeqNumber, SeqNumber, u8), RBCProof>, //需要update
    rbc_ready: HashSet<(SeqNumber, SeqNumber)>,
    rbc_epoch_outputs: HashMap<SeqNumber, HashSet<SeqNumber>>,
    aba_invoke_flags: HashMap<(SeqNumber, SeqNumber), u8>,
    aba_values: HashMap<(SeqNumber, SeqNumber, SeqNumber), [HashSet<PublicKey>; 2]>,
    aba_values_flag: HashMap<(SeqNumber, SeqNumber, SeqNumber), [bool; 2]>,
    aba_mux_values: HashMap<(SeqNumber, SeqNumber, SeqNumber), [HashSet<PublicKey>; 2]>,
    aba_mux_flags: HashMap<(SeqNumber, SeqNumber, SeqNumber), [bool; 2]>,
    aba_outputs: HashMap<(SeqNumber, SeqNumber, SeqNumber), HashSet<PublicKey>>,
    aba_ends: HashMap<(SeqNumber, SeqNumber), u8>,
    leader_set: HashMap<(SeqNumber, SeqNumber), SeqNumber>,
    iter: HashMap<SeqNumber, SeqNumber>, //epoch -> iter
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        signature_service: SignatureService,
        pk_set: PublicKeySet,
        store: Store,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        tx_core: Sender<ConsensusMessage>,
        rx_core: Receiver<ConsensusMessage>,
        network_filter: Sender<FilterInput>,
        commit_channel: Sender<Block>,
    ) -> Self {
        let aggregator = Aggregator::new(committee.clone());
        Self {
            epoch: 0,
            height: committee.id(name) as u64,
            name,
            committee,
            parameters,
            signature_service,
            pk_set,
            store,
            mempool_driver,
            synchronizer,
            network_filter,
            _commit_channel: commit_channel,
            _tx_core: tx_core,
            rx_core,
            aggregator,
            rbc_proofs: HashMap::new(),
            rbc_ready: HashSet::new(),
            rbc_epoch_outputs: HashMap::new(),
            aba_invoke_flags: HashMap::new(),
            aba_values: HashMap::new(),
            aba_mux_values: HashMap::new(),
            aba_values_flag: HashMap::new(),
            aba_mux_flags: HashMap::new(),
            aba_outputs: HashMap::new(),
            aba_ends: HashMap::new(),
            leader_set: HashMap::new(),
            iter: HashMap::new(),
        }
    }

    pub fn rank(epoch: SeqNumber, height: SeqNumber, committee: &Committee) -> usize {
        let r = (epoch as usize) * committee.size() + (height as usize);
        r
    }

    async fn store_block(&mut self, block: &Block) {
        let key: Vec<u8> = block.rank(&self.committee).to_le_bytes().into();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
    }

    async fn commit(&mut self, blocks: Vec<Block>) -> ConsensusResult<()> {
        if blocks.len() > 0 {
            let epoch = blocks[0].epoch;
            let mut digest: Vec<Digest> = Vec::new();
            for block in blocks {
                if !block.payload.is_empty() {
                    info!("Committed {}", block);

                    #[cfg(feature = "benchmark")]
                    for x in &block.payload {
                        info!(
                            "Committed B{}({}) epoch {}",
                            block.height,
                            base64::encode(x),
                            block.epoch,
                        );
                    }
                }
                digest.append(&mut block.payload.clone());
                debug!("Committed {}", block);
            }
            self.cleanup(digest, epoch).await?;
        }
        Ok(())
    }

    async fn cleanup(&mut self, digest: Vec<Digest>, epoch: SeqNumber) -> ConsensusResult<()> {
        self.aggregator.cleanup(epoch);
        self.mempool_driver
            .cleanup(digest, epoch, (self.committee.size() - 1) as SeqNumber)
            .await;
        // Message related to ABA Output message can not be cleared.
        self.rbc_proofs.retain(|(e, ..), _| *e > epoch);
        self.rbc_ready.retain(|(e, ..)| *e > epoch);
        // self.rbc_outputs.retain(|(e, h, ..), _| e * size + h > rank);
        // self.prepare_flags.retain(|(e, h), _| e * size + h > rank);
        self.aba_values.retain(|(e, ..), _| *e > epoch);
        self.aba_mux_values.retain(|(e, ..), _| *e > epoch);
        self.aba_values_flag.retain(|(e, ..), _| *e > epoch);
        self.aba_mux_flags.retain(|(e, ..), _| *e > epoch);
        // self.leader_set.retain(|(e, ..), _| *e > epoch);
        // self.iter.retain(|e, _| *e >= epoch);
        // self.aba_outputs.retain(|(e, h, ..), _| e * size + h > rank);
        // self.aba_ends.retain(|(e, h, ..), _| e * size + h > rank);
        Ok(())
    }

    /************* RBC Protocol ******************/
    #[async_recursion]
    async fn generate_rbc_proposal(&mut self) -> ConsensusResult<()> {
        if self.height < self.parameters.fault {
            return Ok(());
        }
        // Make a new block.
        debug!("start rbc epoch {}", self.epoch);
        let payload = self
            .mempool_driver
            .get(self.parameters.max_payload_size)
            .await;
        let block = Block::new(
            self.name,
            self.epoch,
            self.height,
            payload,
        )
        .await;
        if !block.payload.is_empty() {
            info!("Created {}", block);

            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                // NOTE: This log entry is used to compute performance.
                info!(
                    "Created B{}({}) epoch {}",
                    block.height,
                    base64::encode(x),
                    block.epoch
                );
            }
        }
        debug!("Created {:?}", block);

        //start
        #[cfg(feature = "benchmark")]
        info!("start epoch {} height {}", self.epoch, self.height);

        // Process our new block and broadcast it.
        let message = ConsensusMessage::RBCValMsg(block.clone());
        Synchronizer::transmit(
            message,
            &self.name,
            None,
            &self.network_filter,
            &self.committee,
        )
        .await?;
        self.handle_rbc_val(&block).await?;

        // Wait for the minimum block delay.
        sleep(Duration::from_millis(self.parameters.min_block_delay)).await;

        Ok(())
    }

    async fn handle_rbc_val(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!(
            "processing RBC val epoch {} height {}",
            block.epoch, block.height
        );
        block.verify(&self.committee)?;
        self.store_block(block).await;

        let vote = EchoVote::new(
            self.name,
            block.epoch,
            block.height,
            block,
        )
        .await;
        let message = ConsensusMessage::RBCEchoMsg(vote.clone());

        Synchronizer::transmit(
            message,
            &self.name,
            None,
            &self.network_filter,
            &self.committee,
        )
        .await?;

        self.handle_rbc_echo(&vote).await?;
        Ok(())
    }

    async fn handle_rbc_echo(&mut self, vote: &EchoVote) -> ConsensusResult<()> {
        debug!(
            "processing RBC echo_vote epoch {} height {}",
            vote.epoch, vote.height
        );
        vote.verify(&self.committee)?;

        if let Some(proof) = self.aggregator.add_rbc_echo_vote(vote.clone())? {
            self.rbc_proofs
                .insert((proof.epoch, proof.height, proof.tag), proof);
            self.rbc_ready.insert((vote.epoch, vote.height));
            let ready = ReadyVote::new(
                self.name,
                vote.epoch,
                vote.height,
                vote.digest.clone(),
            )
            .await;
            let message = ConsensusMessage::RBCReadyMsg(ready.clone());
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
            self.handle_rbc_ready(&ready).await?;
        }

        Ok(())
    }

    #[async_recursion]
    async fn handle_rbc_ready(&mut self, vote: &ReadyVote) -> ConsensusResult<()> {
        debug!(
            "processing RBC ready_vote epoch {} height {}",
            vote.epoch, vote.height
        );
        vote.verify(&self.committee)?;

        if let Some(proof) = self.aggregator.add_rbc_ready_vote(vote.clone())? {
            let flag = self.rbc_ready.contains(&(vote.epoch, vote.height));

            self.rbc_proofs
                .insert((proof.epoch, proof.height, proof.tag), proof.clone());

            if !flag && proof.votes.len() as Stake == self.committee.random_coin_threshold() {
                self.rbc_ready.insert((vote.epoch, vote.height));
                let ready = ReadyVote::new(
                    self.name,
                    vote.epoch,
                    vote.height,
                    vote.digest.clone(),
                )
                .await;
                let message = ConsensusMessage::RBCReadyMsg(ready.clone());
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                self.handle_rbc_ready(&ready).await?;
                return Ok(());
            } 
            if proof.votes.len() as Stake == self.committee.quorum_threshold() {
                self.process_rbc_output(vote.epoch, vote.height).await?;
            }
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_rbc_output(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
    ) -> ConsensusResult<()> {
        debug!("processing RBC output epoch {} height {}", epoch, height);
        let outputs = self
            .rbc_epoch_outputs
            .entry(epoch)
            .or_insert(HashSet::new());

        if outputs.insert(height) {
            let iter = *self.iter.entry(epoch).or_insert(0);
            if outputs.len() == self.committee.quorum_threshold() as usize {
                let share = RandomnessShare::new(
                    epoch,
                    iter,
                    0,
                    self.name,
                    self.signature_service.clone(),
                )
                .await;
                let message = ConsensusMessage::LeaderShareMsg(share.clone());
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                self.handle_leader_share(&share).await?; 
            }
        } 
        Ok(())
    }

    async fn handle_sync_request(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        sender: PublicKey,
    ) -> ConsensusResult<()> {
        debug!("processing sync request epoch {} height {}", epoch, height);
        let rank = Core::rank(epoch, height, &self.committee);
        if let Some(bytes) = self.store.read(rank.to_le_bytes().into()).await? {
            let block = bincode::deserialize(&bytes)?;
            let message = ConsensusMessage::SyncReplyMsg(block);
            Synchronizer::transmit(
                message,
                &self.name,
                Some(&sender),
                &self.network_filter,
                &self.committee,
            )
            .await?;
        }
        Ok(())
    }

    async fn handle_sync_reply(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!(
            "processing sync reply epoch {} height {}",
            block.epoch, block.height
        );
        block.verify(&self.committee)?;
        self.store_block(block).await;
        self.process_rbc_output(block.epoch, block.height).await?;
        Ok(())
    }
    /************* RBC Protocol ******************/

    /************* ABA Protocol ******************/
    async fn invoke_aba(
        &mut self,
        epoch: SeqNumber,
        iter: SeqNumber,
        val: u8,
    ) -> ConsensusResult<()> {
        if !self.aba_invoke_flags.contains_key(&(epoch, iter)) {
            self.aba_invoke_flags.insert((epoch, iter), val);
            let aba_val = ABAVal::new(
                self.name,
                epoch,
                iter,
                0,
                val as usize,
                VAL_PHASE,
            )
            .await;
            let message = ConsensusMessage::ABAValMsg(aba_val.clone());
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
            self.handle_aba_val(&aba_val).await?;

            // round 0 Optimization 1: if val = 1, add 1 to bin_value 
            if val == OPT {
                let values = self
                    .aba_values_flag
                    .entry((epoch, iter, 0))
                    .or_insert([false, false]);
                values[OPT as usize] = true;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn handle_aba_val(&mut self, aba_val: &ABAVal) -> ConsensusResult<()> {
        debug!(
            "processing aba val epoch {} iter {}",
            aba_val.epoch, aba_val.iter
        );

        // aba_val.verify()?;

        let values = self
            .aba_values
            .entry((aba_val.epoch, aba_val.iter, aba_val.round))
            .or_insert([HashSet::new(), HashSet::new()]);

        if values[aba_val.val].insert(aba_val.author) {
            let nums = values[aba_val.val].len() as Stake;
            if nums == self.committee.random_coin_threshold()
                && !values[aba_val.val].contains(&self.name)
            {
                //f+1
                let other = ABAVal::new(
                    self.name,
                    aba_val.epoch,
                    aba_val.iter,
                    aba_val.round,
                    aba_val.val,
                    VAL_PHASE,
                )
                .await;
                let message = ConsensusMessage::ABAValMsg(other);
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                values[aba_val.val].insert(self.name);

                // round 0 Optimization 2: receive f+1 1, add 1 to bin_value
                if aba_val.round == 0 && aba_val.val == OPT as usize {
                    let value_flags = self
                        .aba_values_flag
                        .entry((aba_val.epoch, aba_val.iter, aba_val.round))
                        .or_insert([false, false]);
                    value_flags[OPT as usize] = true;
                }
            }

            let nums = values[aba_val.val].len() as Stake;
            if nums == self.committee.quorum_threshold() {
                let values_flag = self
                    .aba_values_flag
                    .entry((aba_val.epoch, aba_val.iter, aba_val.round))
                    .or_insert([false, false]);

                let other_nums = values[aba_val.val ^ 1].len() as Stake;
                if other_nums < self.committee.quorum_threshold() {
                    values_flag[aba_val.val] = true;
                    let mux = ABAVal::new(
                        self.name,
                        aba_val.epoch,
                        aba_val.iter,
                        aba_val.round,
                        aba_val.val,
                        MUX_PHASE,
                    )
                    .await;
                    let message = ConsensusMessage::ABAMuxMsg(mux.clone());
                    Synchronizer::transmit(
                        message,
                        &self.name,
                        None,
                        &self.network_filter,
                        &self.committee,
                    )
                    .await?;
                    self.handle_aba_mux(&mux).await?;
                } else {
                    values_flag[aba_val.val] = true;
                }
            }
        }
        Ok(())
    }

    async fn handle_aba_mux(&mut self, aba_mux: &ABAVal) -> ConsensusResult<()> {
        debug!(
            "processing aba mux epoch {} iter {}",
            aba_mux.epoch, aba_mux.iter
        );
        // aba_mux.verify()?;
        let values = self
            .aba_mux_values
            .entry((aba_mux.epoch, aba_mux.iter, aba_mux.round))
            .or_insert([HashSet::new(), HashSet::new()]);
        if values[aba_mux.val].insert(aba_mux.author) {
            let mux_flags = self
                .aba_mux_flags
                .entry((aba_mux.epoch, aba_mux.iter, aba_mux.round))
                .or_insert([false, false]);

            if !mux_flags[PES as usize] && !mux_flags[OPT as usize] {
                let nums_opt = values[OPT as usize].len();
                let nums_pes = values[PES as usize].len();
                if nums_opt + nums_pes >= self.committee.quorum_threshold() as usize {
                    let value_flags = self
                        .aba_values_flag
                        .entry((aba_mux.epoch, aba_mux.iter, aba_mux.round))
                        .or_insert([false, false]);
                    if value_flags[PES as usize] && value_flags[OPT as usize] {
                        mux_flags[OPT as usize] = nums_opt > 0;
                        mux_flags[PES as usize] = nums_pes > 0;
                    } else if value_flags[OPT as usize] {
                        mux_flags[OPT as usize] =
                            nums_opt >= self.committee.quorum_threshold() as usize;
                    } else {
                        mux_flags[PES as usize] =
                            nums_pes >= self.committee.quorum_threshold() as usize;
                    }
                }

                if mux_flags[PES as usize] || mux_flags[OPT as usize] {
                    let share = RandomnessShare::new(
                        aba_mux.epoch,
                        aba_mux.iter,
                        aba_mux.round,
                        self.name,
                        self.signature_service.clone(),
                    )
                    .await;
                    let message = ConsensusMessage::ABACoinShareMsg(share.clone());
                    Synchronizer::transmit(
                        message,
                        &self.name,
                        None,
                        &self.network_filter,
                        &self.committee,
                    )
                    .await?;
                    self.handle_aba_share(&share).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_aba_share(&mut self, share: &RandomnessShare) -> ConsensusResult<()> {
        debug!(
            "processing coin share epoch {} iter {}",
            share.epoch, share.iter
        );
        share.verify(&self.committee, &self.pk_set)?;
        if let Some(mut coin) = self
            .aggregator
            .add_aba_share_coin(share.clone(), &self.pk_set)?
        {
            // round 0 Optimization 3: coin must be 1
            if share.round == 0 {
                coin = 1;
            }

            // if !mux_flags[coin] && !mux_flags[coin ^ 1] ?
            let mux_flags = self
                .aba_mux_flags
                .entry((share.epoch, share.iter, share.round))
                .or_insert([false, false]);
            let mut val = coin;
            if mux_flags[coin] && !mux_flags[coin ^ 1] {
                self.process_aba_output(share.epoch, share.iter, share.round, coin)
                    .await?;
            } else if !mux_flags[coin] && mux_flags[coin ^ 1] {
                val = coin ^ 1;
            }
            self.aba_adcance_round(share.epoch, share.iter, share.round + 1, val)
                .await?;
        }
        Ok(())
    }

    async fn handle_leader_share(&mut self, share: &RandomnessShare) -> ConsensusResult<()> {
        debug!(
            "processing leader share epoch {} iter {}",
            share.epoch, share.iter
        );
        share.verify(&self.committee, &self.pk_set)?;
        if let Some(leader) = self
            .aggregator
            .add_share_leader(share.clone(), &self.pk_set)?
        {
            self.leader_set.insert((share.epoch, share.iter), leader as SeqNumber);
            let outputs = self
                .rbc_epoch_outputs
                .entry(share.epoch)
                .or_insert(HashSet::new());

            // Leader Election is earlier than 2f+1 RBC outputs ?
            let iter = *self.iter.entry(share.epoch).or_insert(0);
            if outputs.contains(&(leader as SeqNumber)) {
                self.invoke_aba(share.epoch, iter, OPT).await?;
            } else {
                self.invoke_aba(share.epoch, iter, PES).await?;
            }
        }
        Ok(())
    }

    async fn handle_aba_output(&mut self, output: &ABAOutput) -> ConsensusResult<()> {
        debug!(
            "processing aba output epoch {} iter {}",
            output.epoch, output.iter
        );
        // output.verify()?;
        let used = self
            .aba_outputs
            .entry((output.epoch, output.iter, output.round))
            .or_insert(HashSet::new());
        if used.insert(output.author)
            && used.len() == self.committee.random_coin_threshold() as usize
        {
            if !used.contains(&self.name) {
                let output = ABAOutput::new(
                    self.name,
                    output.epoch,
                    output.iter,
                    output.round,
                    output.val,
                )
                .await;
                let message = ConsensusMessage::ABAOutputMsg(output);
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
                used.insert(self.name);
            }
            self.process_aba_output(output.epoch, output.iter, output.round, output.val)
                .await?;
        }

        Ok(())
    }

    async fn process_aba_output(
        &mut self,
        epoch: SeqNumber,
        iter: SeqNumber,
        round: SeqNumber,
        val: usize,
    ) -> ConsensusResult<()> {
        debug!("ABA(epoch {} iter {}) end output({})", epoch, iter, val);

        if !self.aba_ends.contains_key(&(epoch, iter)) {
            //step1. send output message
            let used = self
                .aba_outputs
                .entry((epoch, iter, round))
                .or_insert(HashSet::new());
            if used.insert(self.name) {
                let output = ABAOutput::new(
                    self.name,
                    epoch,
                    iter,
                    round,
                    val,
                )
                .await;
                let message = ConsensusMessage::ABAOutputMsg(output);
                Synchronizer::transmit(
                    message,
                    &self.name,
                    None,
                    &self.network_filter,
                    &self.committee,
                )
                .await?;
            }
            info!("ABA(epoch {}, iter {}) output {}", epoch, iter, val);
            self.aba_ends.insert((epoch, iter), val as u8);

            if val as u8 == OPT {
                // If leader is not elected, handle later.
                if !self.leader_set.contains_key(&(epoch, iter)) {
                    return Ok(());
                }
                let leader = *self.leader_set.get(&(epoch, iter)).unwrap();
                self.handle_epoch_end(epoch, leader).await?;
            } else {
                self.advance_iter(iter + 1).await?;
            }
        }
        Ok(())
    }

    async fn aba_adcance_round(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        round: SeqNumber,
        val: usize,
    ) -> ConsensusResult<()> {
        if !self.aba_ends.contains_key(&(epoch, height)) {
            let aba_val = ABAVal::new(
                self.name,
                epoch,
                height,
                round,
                val,
                VAL_PHASE,
            )
            .await;
            let message = ConsensusMessage::ABAValMsg(aba_val.clone());
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
            self.handle_aba_val(&aba_val).await?;
        }
        Ok(())
    }
    /************* ABA Protocol ******************/

    pub async fn handle_epoch_end(&mut self, epoch: SeqNumber, height: SeqNumber) -> ConsensusResult<()> {
        //end epoch
        #[cfg(feature = "benchmark")]
        info!("end epoch {} height {}", epoch, self.height);

        let mut data: Vec<Block> = Vec::new();

        if let Some(block) = self
            .synchronizer
            .block_request(epoch, height, &self.committee)
            .await?
        {
            if self.parameters.exp > 0 {
                if !self.mempool_driver.verify(block.clone()).await? {
                    return Ok(());
                }
            }
            data.push(block);
        }
        self.commit(data).await?;
        self.advance_epoch(epoch + 1).await?;

        Ok(())
    }

    pub async fn advance_epoch(&mut self, epoch: SeqNumber) -> ConsensusResult<()> {
        if epoch > self.epoch {
            self.epoch = epoch;
            self.generate_rbc_proposal().await?;
        }
        Ok(())
    }

    pub async fn advance_iter(&mut self, iter: SeqNumber) -> ConsensusResult<()> {
        let self_iter = self.iter.entry(self.epoch).or_insert(0);
        if iter > *self_iter {
            *self_iter = iter;
            let share = RandomnessShare::new(
                self.epoch,
                *self_iter,
                0,
                self.name,
                self.signature_service.clone(),
            )
            .await;
            let message = ConsensusMessage::LeaderShareMsg(share.clone());
            Synchronizer::transmit(
                message,
                &self.name,
                None,
                &self.network_filter,
                &self.committee,
            )
            .await?;
            self.handle_leader_share(&share).await?;
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        if let Err(e) = self.generate_rbc_proposal().await {
            panic!("protocol invoke failed! error {}", e);
        }
        loop {
            let result = tokio::select! {
                Some(message) = self.rx_core.recv() => {
                    if self.height<self.parameters.fault{
                        continue;
                    }
                    match message {
                        ConsensusMessage::RBCValMsg(block) => self.handle_rbc_val(&block).await,
                        ConsensusMessage::RBCEchoMsg(evote) => self.handle_rbc_echo(&evote).await,
                        ConsensusMessage::RBCReadyMsg(rvote) => self.handle_rbc_ready(&rvote).await,
                        ConsensusMessage::LeaderShareMsg(share) => self.handle_leader_share(&share).await,
                        ConsensusMessage::ABAValMsg(val) => self.handle_aba_val(&val).await,
                        ConsensusMessage::ABAMuxMsg(mux) => self.handle_aba_mux(&mux).await,
                        ConsensusMessage::ABACoinShareMsg(share) => self.handle_aba_share(&share).await,
                        ConsensusMessage::ABAOutputMsg(output) => self.handle_aba_output(&output).await,
                        ConsensusMessage::LoopBackMsg(epoch, height) => self.handle_epoch_end(epoch, height).await,
                        ConsensusMessage::SyncRequestMsg(epoch, height, sender) => self.handle_sync_request(epoch, height, sender).await,
                        ConsensusMessage::SyncReplyMsg(block) => self.handle_sync_reply(&block).await,
                    }
                },
                else => break,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
