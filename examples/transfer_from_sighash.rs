use std::error::Error as StdErr;

use ckb_crypto::secp::Privkey;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types as json_types;
use ckb_sdk::constants::{
    CROSSCHAIN_LOCK_CODE_HASH, CROSSCHAIN_METADATA_CODE_HASH, CROSSCHAIN_METADATA_TX_HASH,
    CROSSCHAIN_REQUEST_CODE_HASH, CROSSCHAIN_REQUEST_TX_HASH, SIGHASH_TX_HASH, TYPE_ID_CODE_HASH,
};
use ckb_sdk::helper::{cs_address, cs_hash, cs_token_config, cs_uint32, cs_uint64};
use ckb_sdk::traits::{CellCollector, CellQueryOptions, ValueRangeOption};
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH, crosschain, rpc::CkbRpcClient, traits::DefaultCellCollector,
    Address, HumanCapacity, SECP256K1,
};
use ckb_types::core::{DepType, TransactionBuilder};
use ckb_types::h256;
use ckb_types::packed::{CellDep, CellInput, ScriptOpt};
use ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionView},
    packed::{Byte32, Bytes as OtherBytes, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
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
    /// deploy crosschain data or ckb->axon crosschain tx
    #[clap(long, value_name = "TYPE", default_value = "0")]
    tx_type: u16,

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
    let tx_type = args.tx_type;

    // sender key is the lock_arg of wallet 1 from https://zero2ckb.ckbapp.dev/learn
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

    // get tx hash, code hash from https://pudge.explorer.nervos.org/scripts#secp256k1_blake160
    let lock_secp_tx_hash = Byte32::from_slice(SIGHASH_TX_HASH.as_bytes()).unwrap();
    let secp256k1_out_point = OutPoint::new(lock_secp_tx_hash, 0);
    let secp256k1_data_dep = CellDep::new_builder()
        .out_point(secp256k1_out_point.clone())
        .dep_type(DepType::DepGroup.into())
        .build();

    let mut tx = TransactionBuilder::default().build();
    println!("{:?}", tx);
    if tx_type == 0 {
        println!("deploy crosschain metadata");
        tx = build_deploy_crosschain_metadata_tx(&args, sender, secp256k1_data_dep)?;
    } else {
        println!("create crosschain tx, from ckb to axon");
        tx = build_ckb_axon_tx(&args, sender, secp256k1_data_dep)?;
    }

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

fn build_deploy_crosschain_metadata_tx(
    args: &Args,
    sender: Script,
    secp256k1_data_dep: CellDep,
) -> Result<TransactionView, Box<dyn StdErr>> {
    let mut cell_collector =
        DefaultCellCollector::new(args.ckb_indexer.as_str(), args.ckb_rpc.as_str());

    // crosschain-metadata dep cell
    let crosschain_metadata_tx_hash =
        Byte32::from_slice(CROSSCHAIN_METADATA_TX_HASH.as_bytes()).unwrap();
    let crosschain_metadata_out_point = OutPoint::new(crosschain_metadata_tx_hash, 0);
    let crosschain_metadata_dep = CellDep::new_builder()
        .out_point(crosschain_metadata_out_point.clone())
        .dep_type(DepType::Code.into())
        .build();

    let base_query = {
        let mut query = CellQueryOptions::new_lock(sender.clone());
        query.data_len_range = Some(ValueRangeOption::new_exact(0));
        query
    };
    let query = {
        let mut query = base_query.clone();
        query.min_total_capacity = 100;
        query
    };
    let (more_cells, _more_capacity) = cell_collector.collect_live_cells(&query, false)?;
    let input_cap: u64 = more_cells[0].output.capacity().unpack();
    println!("capacity: {}, size: {}", input_cap, more_cells.len());
    let input = CellInput::new(more_cells[0].out_point.clone(), 0);

    // prepare metadata cell data
    let metadata = crosschain::Metadata::new_builder()
        .chain_id(5.into())
        .ckb_fee_ratio(cs_uint32(100))
        .stake_typehash(cs_hash(&Byte32::default()))
        .token_config(cs_token_config(&vec![]))
        .build();

    // crosschain-metadata lock script
    let code_hash = Byte32::from_slice(CROSSCHAIN_METADATA_CODE_HASH.as_bytes()).unwrap();
    let meta_script = Script::new_builder()
        .code_hash(code_hash)
        .hash_type(ScriptHashType::Data.into())
        .args(sender.args())
        .build();

    // crosschain-metadata type script
    let type_script = build_type_id_script(&input, 0);
    // output cell
    let output = CellOutput::new_builder()
        .lock(meta_script)
        .type_(type_script)
        .capacity(args.capacity.0.pack())
        .build();
    let out_cap: u64 = output.capacity().unpack();
    println!("out cap {}", out_cap);

    let remain_cap = input_cap - out_cap - 100_000_000;
    let output1 = CellOutput::new_builder()
        .lock(sender)
        .capacity(remain_cap.pack())
        .build();

    let cell_deps = vec![crosschain_metadata_dep, secp256k1_data_dep];
    let outputs_data = vec![metadata.as_bytes().pack(), Bytes::new().pack()];
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output(output1)
        .outputs_data(outputs_data)
        .cell_deps(cell_deps.clone())
        .build();

    tx.as_advanced_builder()
        .set_cell_deps(Vec::new())
        .cell_deps(cell_deps.into_iter().collect::<Vec<_>>().pack())
        .build();

    let key = Privkey::from_slice(args.sender_key.as_bytes());
    let tx = sign_tx(tx, &key);

    Ok(tx)
}

fn build_ckb_axon_tx(
    args: &Args,
    sender: Script,
    secp256k1_data_dep: CellDep,
) -> Result<TransactionView, Box<dyn StdErr>> {
    let mut cell_collector =
        DefaultCellCollector::new(args.ckb_indexer.as_str(), args.ckb_rpc.as_str());

    // crosschain-metadata dep cell
    // get tx hash created by build_deploy_crosschain_metadata_tx
    let crosschain_metadata_tx_hash = Byte32::from_slice(
        h256!("0xbdee4ff5b30ee9be7b644f3e55d080adc64fdab4425107076cf1e192163a9dc9").as_bytes(),
    )
    .unwrap();
    let contract_out_point = OutPoint::new(crosschain_metadata_tx_hash, 0);
    let contract_dep = CellDep::new_builder()
        .out_point(contract_out_point.clone())
        .dep_type(DepType::Code.into())
        .build();

    // crosschain-request dep cell
    let crosschain_request_tx_hash =
        Byte32::from_slice(CROSSCHAIN_REQUEST_TX_HASH.as_bytes()).unwrap();
    let cs_req_out_point = OutPoint::new(crosschain_request_tx_hash, 0);
    let cs_req_dep = CellDep::new_builder()
        .out_point(cs_req_out_point.clone())
        .dep_type(DepType::Code.into())
        .build();

    let base_query = {
        let mut query = CellQueryOptions::new_lock(sender.clone());
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

    // crosschain-lock lock script
    // code hash of crosschain-lock
    let lock_code_hash = Byte32::from_slice(CROSSCHAIN_LOCK_CODE_HASH.as_bytes()).unwrap();
    // type id of cross-chain metadata, the typeid of build_deploy_crosschain_metadata_tx calculated in build_type_id_script
    let lock_args =
        h256!("0x9d150f92179f315fffe35eb3ef79d9e66bc37de1764b2fe440c264c956facdae").as_bytes();
    let lock_script = Script::new_builder()
        .code_hash(lock_code_hash)
        .hash_type(ScriptHashType::Type.into())
        .args(lock_args.pack())
        .build();
    // crosschain-lock cell
    let output0 = CellOutput::new_builder()
        .lock(lock_script.clone())
        .capacity(16_000_000_000.pack())
        .build();

    let request_code_hash = Byte32::from_slice(CROSSCHAIN_REQUEST_CODE_HASH.as_bytes()).unwrap();
    // prepare corsschain request script
    let transfer_args = crosschain::Transfer::new_builder()
        .axon_address(cs_address(&[0u8; 20]))
        .ckb_amount(cs_uint64(450))
        .erc20_address(cs_address(&[0u8; 20]))
        .build();

    let request_script = Script::new_builder()
        .code_hash(request_code_hash)
        .hash_type(ScriptHashType::Data1.into())
        .args(transfer_args.as_bytes().pack())
        .build();
    // corsschain-request cell
    let output1 = CellOutput::new_builder()
        .capacity(26_000_000_000.pack())
        .lock(sender.clone())
        .type_(Some(request_script).pack())
        .build();

    let input_cap: u64 = more_cells[0].output.capacity().unpack();
    let output0_cap: u64 = output0.capacity().unpack();
    let output1_cap: u64 = output1.capacity().unpack();
    let fee = 100_000_000;
    let remain_cap: u64 = input_cap - output0_cap - output1_cap - fee;
    println!(
        "input {}, out0 {}, out1 cap {} fee {}, remain {}",
        input_cap, output0_cap, output1_cap, fee, remain_cap
    );
    let output2 = CellOutput::new_builder()
        .lock(sender.clone())
        .capacity(remain_cap.pack())
        .build();

    let cell_deps = vec![contract_dep, secp256k1_data_dep, cs_req_dep];
    let outputs_data = vec![
        Bytes::new().pack(),
        Bytes::new().pack(),
        Bytes::new().pack(),
    ];

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output0)
        .output(output1)
        .output(output2)
        .outputs_data(outputs_data)
        .cell_deps(cell_deps.clone())
        .build();

    tx.as_advanced_builder()
        .set_cell_deps(Vec::new())
        .cell_deps(cell_deps.into_iter().collect::<Vec<_>>().pack())
        .build();

    let key = Privkey::from_slice(args.sender_key.as_bytes());

    let tx = sign_tx(tx, &key);

    Ok(tx)
}

fn build_type_id_script(input: &CellInput, output_index: u64) -> ScriptOpt {
    let mut blake2b = new_blake2b();
    blake2b.update(&input.as_slice());
    blake2b.update(&output_index.to_le_bytes());
    let mut ret = [0; 32];
    blake2b.finalize(&mut ret);
    let script_arg = Bytes::from(ret.to_vec());
    let code_hash = Byte32::from_slice(TYPE_ID_CODE_HASH.as_bytes()).unwrap();
    let script = Script::new_builder()
        .code_hash(code_hash)
        .hash_type(ScriptHashType::Type.into())
        .args(script_arg.pack())
        .build();

    println!("type id {}", script.calc_script_hash().to_string());

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
