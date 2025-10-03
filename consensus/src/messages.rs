use crate::config::Committee;
use crate::core::SeqNumber;
use crypto::{Digest, Hash, PublicKey, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt;
use threshold_crypto::{SignatureShare};

#[cfg(test)]
#[path = "tests/messages_tests.rs"]
pub mod messages_tests;

// daniel: Add view, height, fallback in Block, Vote and QC
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub author: PublicKey,
    pub epoch: SeqNumber,  //
    pub height: SeqNumber, // author`s id
    pub payload: Vec<Digest>,
}

impl Block {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        payload: Vec<Digest>,
    ) -> Self {
        let block = Self {
            author,
            epoch,
            height,
            payload,
        };

        Self { ..block }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    // block`s rank
    pub fn rank(&self, committee: &Committee) -> usize {
        let r = (self.epoch as usize) * committee.size() + (self.height as usize);
        r
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, epoch {},  height {}, payload_len {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B(author {}, epoch {},  height {}, payload_len {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
            self.payload.iter().map(|x| x.size()).sum::<usize>(),
        )
    }
}

/************************** RBC Struct ************************************/
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct EchoVote {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub digest: Digest,
}

impl EchoVote {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        block: &Block,
    ) -> Self {
        let vote = Self {
            author,
            epoch,
            height,
            digest: block.digest(),
        };
        return vote;
    }

    pub fn rank(&self, committee: &Committee) -> usize {
        let r = (self.epoch as usize) * committee.size() + (self.height as usize);
        r
    }
}

impl Hash for EchoVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.digest.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for EchoVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: EchoVote(author {}, epoch {},  height {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
        )
    }
}

impl fmt::Display for EchoVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: EchoVote(author {}, epoch {},  height {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ReadyVote {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub digest: Digest,
}

impl ReadyVote {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        height: SeqNumber,
        digest: Digest,
    ) -> Self {
        let vote = Self {
            author,
            epoch,
            height,
            digest,
        };
        return vote;
    }

    pub fn rank(&self, committee: &Committee) -> usize {
        let r = (self.epoch as usize) * committee.size() + (self.height as usize);
        r
    }
}

impl Hash for ReadyVote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.digest.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ReadyVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: ReadyVote(author {}, epoch {},  height {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
        )
    }
}

impl fmt::Display for ReadyVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: ReadyVote(author {}, epoch {},  height {})",
            self.digest(),
            self.author,
            self.epoch,
            self.height,
        )
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct RBCProof {
    pub epoch: SeqNumber,
    pub height: SeqNumber,
    pub votes: Vec<PublicKey>,
    pub tag: u8,
}

impl RBCProof {
    pub fn new(
        epoch: SeqNumber,
        height: SeqNumber,
        votes: Vec<PublicKey>,
        tag: u8,
    ) -> Self {
        Self {
            epoch,
            height,
            votes,
            tag,
        }
    }

    // pub fn rank(&self, committee: &Committee) -> usize {
    //     let r =
    //         ((self.epoch as usize) * committee.size() + (self.height as usize)) % MAX_BLOCK_BUFFER;
    //     r
    // }
}

impl fmt::Debug for RBCProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "RBCProof(epoch {}, height {},tag {})",
            self.epoch, self.height, self.tag,
        )
    }
}

impl fmt::Display for RBCProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "RBCProof(epoch {},  height {},tag {})",
            self.epoch, self.height, self.tag,
        )
    }
}

/************************** RBC Struct ************************************/

/************************** prepare Struct ************************************/
// #[derive(Serialize, Deserialize, Default, Clone)]
// pub struct Prepare {
//     pub author: PublicKey,
//     pub epoch: SeqNumber,
//     pub height: SeqNumber,
//     pub val: u8,
//     pub signature: Signature,
// }

// impl Prepare {
//     pub async fn new(
//         author: PublicKey,
//         epoch: SeqNumber,
//         height: SeqNumber,
//         val: u8,
//         mut signature_service: SignatureService,
//     ) -> Self {
//         let mut prepare = Self {
//             author,
//             epoch,
//             height,
//             val,
//             signature: Signature::default(),
//         };
//         prepare.signature = signature_service.request_signature(prepare.digest()).await;
//         return prepare;
//     }

//     pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
//         // Ensure the authority has voting rights.
//         let voting_rights = committee.stake(&self.author);
//         ensure!(
//             voting_rights > 0,
//             ConsensusError::UnknownAuthority(self.author)
//         );

//         // Check the signature.
//         self.signature.verify(&self.digest(), &self.author)?;

//         Ok(())
//     }

//     pub fn rank(&self, committee: &Committee) -> usize {
//         let r =
//             ((self.epoch as usize) * committee.size() + (self.height as usize)) % MAX_BLOCK_BUFFER;
//         r
//     }
// }

// impl Hash for Prepare {
//     fn digest(&self) -> Digest {
//         let mut hasher = Sha512::new();
//         hasher.update(self.author.0);
//         hasher.update(self.epoch.to_le_bytes());
//         hasher.update(self.height.to_le_bytes());
//         hasher.update(self.val.to_le_bytes());
//         Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
//     }
// }

// impl fmt::Debug for Prepare {
//     fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
//         write!(
//             f,
//             "{}: Prepare(author {}, epoch {},  height {}, val {})",
//             self.digest(),
//             self.author,
//             self.epoch,
//             self.height,
//             self.val
//         )
//     }
// }
/************************** pre-prepare Struct ************************************/

/************************** ABA Struct ************************************/
#[derive(Clone, Serialize, Deserialize)]
pub struct ABAVal {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub iter: SeqNumber,
    pub round: SeqNumber, //ABA 的轮数
    pub phase: u8,        //ABA 的阶段（VAL，AUX）
    pub val: usize,
}

impl ABAVal {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        iter: SeqNumber,
        round: SeqNumber,
        val: usize,
        phase: u8,
    ) -> Self {
        let aba_val = Self {
            author,
            epoch,
            iter,
            round,
            val,
            phase,
        };
        return aba_val;
    }

    pub fn rank(&self, committee: &Committee) -> usize {
        let r = (self.epoch as usize) * committee.size() + (self.iter as usize);
        r
    }
}

impl Hash for ABAVal {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.iter.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ABAVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ABAVal(author{},epoch {},iter {},round {},phase {},val {})",
            self.author, self.epoch, self.iter, self.round, self.phase, self.val
        )
    }
}

impl fmt::Display for ABAVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ABAVal(author{},epoch {},iter {},round {},phase {},val {})",
            self.author, self.epoch, self.iter, self.round, self.phase, self.val
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ABAOutput {
    pub author: PublicKey,
    pub epoch: SeqNumber,
    pub iter: SeqNumber,
    pub round: SeqNumber,
    pub val: usize,
}

impl ABAOutput {
    pub async fn new(
        author: PublicKey,
        epoch: SeqNumber,
        iter: SeqNumber,
        round: SeqNumber,
        val: usize,
    ) -> Self {
        let out = Self {
            author,
            epoch,
            iter,
            round,
            val,
        };
        return out;
    }

    pub fn rank(&self, committee: &Committee) -> usize {
        let r = (self.epoch as usize) * committee.size() + (self.iter as usize);
        r
    }
}

impl Hash for ABAOutput {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.iter.to_le_bytes());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ABAOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ABAOutput(author {},epoch {},iter {},round {},val {})",
            self.author, self.epoch, self.iter, self.round, self.val
        )
    }
}

/************************** ABA Struct ************************************/

/************************** Share Coin Struct ************************************/
#[derive(Clone, Serialize, Deserialize)]
pub struct RandomnessShare {
    pub epoch: SeqNumber,
    pub iter: SeqNumber,
    pub round: SeqNumber,
    pub author: PublicKey,
    pub signature_share: SignatureShare,
}

impl RandomnessShare {
    pub async fn new(
        epoch: SeqNumber,
        iter: SeqNumber,
        round: SeqNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(round.to_le_bytes());
        hasher.update(iter.to_le_bytes());
        hasher.update(epoch.to_le_bytes());
        let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
        let signature_share = signature_service
            .request_tss_signature(digest)
            .await
            .unwrap();
        Self {
            round,
            iter,
            epoch,
            author,
            signature_share,
        }
    }

    // pub fn verify(&self, committee: &Committee, pk_set: &PublicKeySet) -> ConsensusResult<()> {
    //     // Ensure the authority has voting rights.
    //     ensure!(
    //         committee.stake(&self.author) > 0,
    //         ConsensusError::UnknownAuthority(self.author)
    //     );
    //     let tss_pk = pk_set.public_key_share(committee.id(self.author));
    //     // Check the signature.
    //     ensure!(
    //         tss_pk.verify(&self.signature_share, &self.digest()),
    //         ConsensusError::InvalidThresholdSignature(self.author)
    //     );

    //     Ok(())
    // }
}

impl Hash for RandomnessShare {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.iter.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for RandomnessShare {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "RandomnessShare (author {}, iter {},round {})",
            self.author, self.iter, self.round,
        )
    }
}
/************************** Share Coin Struct **************************/
