use std::error::Error as StdErr;

use ckb_crypto::secp::{Privkey};
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types as json_types;
use ckb_sdk::helper::{cs_hash, cs_token_config, cs_uint32};
use ckb_sdk::traits::{CellCollector, CellQueryOptions, ValueRangeOption};
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    crosschain, helper,
    rpc::CkbRpcClient,
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{transfer::CapacityTransferBuilder, CapacityBalancer, TxBuilder},
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    Address, HumanCapacity, ScriptId, SECP256K1,
};
use ckb_types::core::{TransactionBuilder, DepType};
use ckb_types::packed::{CellDep, CellInput, ScriptOpt};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    packed::{Byte32, Bytes as OtherBytes, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use ckb_types::{h160, h256};
use clap::Parser;

/// Transfer some CKB from one sighash address to other address
/// # Example:
///     ./target/debug/examples/transfer_from_sighash \
///       --sender-key <key-hex> \
///       --receiver <address> \
///       --capacity 61.0
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,

    /// The receiver address
    #[clap(long, value_name = "ADDRESS")]
    receiver: Address,

    /// The capacity to transfer (unit: CKB, example: 102.43)
    #[clap(long, value_name = "CKB")]
    capacity: HumanCapacity,

    /// CKB rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8114")]
    ckb_rpc: String,

    /// CKB indexer rpc url
    #[clap(long, value_name = "URL", default_value = "http://127.0.0.1:8116")]
    ckb_indexer: String,
}

fn main() -> Result<(), Box<dyn StdErr>> {
    // Parse arguments
    let args = Args::parse();
    let sender_key = secp256k1::SecretKey::from_slice(args.sender_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))?;
    let sender = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    let tx = build_transfer_tx(&args, sender, sender_key)?;

    // Send transaction
    let json_tx = json_types::TransactionView::from(tx);
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
    let _tx_hash = CkbRpcClient::new(args.ckb_rpc.as_str())
        .send_transaction(json_tx.inner, outputs_validator)
        .expect("send transaction");
    println!(">>> tx sent! <<<");

    Ok(())
}

fn build_type_id_script(input: &CellInput, output_index: u64) -> ScriptOpt {
    let mut blake2b = new_blake2b();
    blake2b.update(&input.as_slice());
    blake2b.update(&output_index.to_le_bytes());
    let mut ret = [0; 32];
    blake2b.finalize(&mut ret);
    let script_arg = Bytes::from(ret.to_vec());
    pub const TYPE_ID_CODE_HASH: H256 = h256!("0x545950455f4944");
    let code_hash = Byte32::from_slice(
        TYPE_ID_CODE_HASH.as_bytes(),
    )
    .unwrap();
    let script = Script::new_builder()
        .code_hash(code_hash)
        .hash_type(ScriptHashType::Type.into())
        .args(script_arg.pack())
        .build();

    ScriptOpt::new_builder().set(Some(script)).build()
}

pub fn sign_tx(tx: TransactionView, key: &Privkey) -> TransactionView {
    let mut signed_witnesses: Vec<OtherBytes> = Vec::new();
    let mut blake2b = new_blake2b();
    blake2b.update(&tx.hash().raw_data());
    // digest the first witness
    let witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let witness_size = witness.as_bytes().len() as u64;
    let mut message = [0u8; 32];
    blake2b.update(&witness_size.to_le_bytes());
    blake2b.update(&witness.as_bytes());
    blake2b.finalize(&mut message);
    let message = H256::from(message);
    let sig = key.sign_recoverable(&message).expect("sign");
    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(sig.serialize())).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

fn build_transfer_tx(
    args: &Args,
    sender: Script,
    sender_key: secp256k1::SecretKey,
) -> Result<TransactionView, Box<dyn StdErr>> {
    // Build ScriptUnlocker
    // let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    // let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    // let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    // let mut unlockers = HashMap::default();
    // unlockers.insert(
    //     sighash_script_id,
    //     Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    // );

    // Build CapacityBalancer
    // let placeholder_witness = WitnessArgs::new_builder()
    //     .lock(Some(Bytes::from(vec![0u8; 65])).pack())
    //     .build();
    // let balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    // let mut ckb_client = CkbRpcClient::new(args.ckb_rpc.as_str());
    // let cell_dep_resolver = {
    //     let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
    //     DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    // };
    // let header_dep_resolver = DefaultHeaderDepResolver::new(args.ckb_rpc.as_str());
    let mut cell_collector =
        DefaultCellCollector::new(args.ckb_indexer.as_str(), args.ckb_rpc.as_str());
    // let tx_dep_provider = DefaultTransactionDependencyProvider::new(args.ckb_rpc.as_str(), 10);

    // // Build the transaction
    // let output = CellOutput::new_builder()
    //     .lock(Script::from(&args.receiver))
    //     .capacity(args.capacity.0.pack())
    //     .build();

    // crosschain-metadata dep cell
    let crosschain_metadata_tx_hash = Byte32::from_slice(
        h256!("0xbb08fe0727449919a5d9f7d8d3333d57d56730dcab9ccfd1ba6ca47c7c0ae9bf").as_bytes(),
    )
    .unwrap();

    let contract_out_point = OutPoint::new(crosschain_metadata_tx_hash, 0);
    let contract_dep = CellDep::new_builder()
        .out_point(contract_out_point.clone())
        .dep_type(DepType::Code.into())
        .build();

    // get tx hash, code hash from https://pudge.explorer.nervos.org/scripts#secp256k1_blake160
    let lock_secp_tx_hash = Byte32::from_slice(
        h256!("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37").as_bytes(),
    )
    .unwrap();
    let secp256k1_out_point = OutPoint::new(lock_secp_tx_hash, 0);
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point.clone())
        .dep_type(DepType::DepGroup.into())
        .build();

    let secp_code_hash = SIGHASH_TYPE_HASH;
    // sender_pubkey is the lock_arg of wallet1 from https://zero2ckb.ckbapp.dev/learn
    let sender_pubkey =
        Bytes::from(h160!("0x43d509d97f26007a285f39241cffcd411157196c").as_bytes());

    let lock_script = Script::new_builder()
        .code_hash(secp_code_hash.pack())
        .hash_type(ScriptHashType::Type.into())
        .args(sender_pubkey.pack())
        .build();

    let base_query = {
        let mut query = CellQueryOptions::new_lock(lock_script.clone());
        query.data_len_range = Some(ValueRangeOption::new_exact(0));
        query
    };
    let query = {
        let mut query = base_query.clone();
        query.min_total_capacity = 100;
        query
    };
    let (more_cells, _more_capacity) = cell_collector.collect_live_cells(&query, false)?;
    println!("capacity: {}, size: {}", _more_capacity, more_cells.len());
    let input = CellInput::new(more_cells[0].out_point.clone(), 0);
    for cell in more_cells {
        let cap = cell.output.capacity();
        println!("{:?}, capacity: {:#x}", cell, cap);
    }

    // prepare metadata cell data
    let metadata = crosschain::Metadata::new_builder()
        .chain_id(5.into())
        .ckb_fee_ratio(cs_uint32(100))
        .stake_typehash(cs_hash(&Byte32::default()))
        .token_config(cs_token_config(&vec![]))
        .build();

    // crosschain-metadata lock script
    let code_hash = Byte32::from_slice(
        h256!("0x4f0eac26544fe1ed861711ba7cb9379c47b792c08a7ed1e22875e4d5a2a0fdc2").as_bytes(),
    )
    .unwrap();
    let meta_script = Script::new_builder()
        .code_hash(code_hash)
        .hash_type(ScriptHashType::Data.into())
        .args(sender_pubkey.pack())
        .build();

    // crosschain-metadata type script
    let type_script = build_type_id_script(&input, 0);

    // output cell
    let output = CellOutput::new_builder()
        .lock(meta_script)
        .type_(type_script)
        .capacity(args.capacity.0.pack())
        .build();

    let cell_deps = vec![contract_dep, secp256k1_data_dep];
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(metadata.as_bytes().pack())
        .cell_deps(cell_deps.clone())
        .build();

    tx.as_advanced_builder()
        .set_cell_deps(Vec::new())
        .cell_deps(cell_deps.into_iter().collect::<Vec<_>>().pack())
        .build();

    let key = Privkey::from_slice(
        h256!("0xdd50cac37ec6dd12539a968c1a2cbedda75bd8724f7bcad486548eaabb87fc8b").as_bytes(),
    );

    let tx = sign_tx(tx, &key);

    Ok(tx)
}
