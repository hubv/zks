use zksync_types::{
    api::{
        state_override::StateOverride, Block, BlockId, BlockIdVariant, BlockNumber, Log,
        Transaction, TransactionId, TransactionReceipt, TransactionVariant,
    },
    transaction_request::CallRequest,
    web3::{Bytes, FeeHistory, Index, SyncState},
    Address, H256, U256, U64,
};
use zksync_web3_decl::{
    jsonrpsee::core::{async_trait, RpcResult},
    namespaces::EthNamespaceServer,
    types::{Filter, FilterChanges},
    error::Web3Error,
};

use crate::web3::EthNamespace;

use serde::{Serialize, Deserialize};
use serde_json::{Value, from_reader};
use std::{error::Error, fs::File};
use std::io::{self, prelude::*, BufReader, BufRead};

const PFC_FILE_PATH: &str = "/data01/full_node/PFC.json";

// 定义 AccountState 结构体
#[derive(Serialize, Deserialize)]
struct AccountState {
    nonce: Option<String>,
    code: String,
    balance: Option<String>,
    state: Option<String>,
}

async fn save_pfc_to_file(contracts: Vec<String>) -> Result<bool, io::Error> {
    let accounts = contracts
        .into_iter()
        .map(|b| AccountState {
            nonce: None,
            code: b,
            balance: None,
            state: None,
        })
        .collect::<Vec<_>>();

    // 构建最终的 JSON 对象
    let result = serde_json::to_string_pretty(&accounts.into_iter().enumerate().map(|(i, a)| if i<10 {(format!("0xceeb00000000000000000000000000000000000{}", i), a)} else {(format!("0xbeef00000000000000000000000000000000000{}", i-10), a)} ).collect::<std::collections::HashMap<_, _>>())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to serialize data: {}", e)))?;

    // 写入文件
    let mut file = File::create(PFC_FILE_PATH)?;
    file.write_all(result.as_bytes())?;

    Ok(true)
}

/// 从文件中读取 StateOverride 数据
fn read_state_override_from_file(file_path: &str) -> Result<Option<StateOverride>, io::Error>  {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let overrides: StateOverride = serde_json::from_reader(reader)?; // 假设使用 serde_json 来反序列化
    Ok(Some(overrides))
}

#[async_trait]
impl EthNamespaceServer for EthNamespace {
    async fn get_block_number(&self) -> RpcResult<U64> {
        self.get_block_number_impl()
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn chain_id(&self) -> RpcResult<U64> {
        Ok(self.chain_id_impl())
    }

    async fn call(
        &self,
        req: CallRequest,
        block: Option<BlockIdVariant>,
        state_override: Option<StateOverride>,
    ) -> RpcResult<Bytes> {
        self.call_impl(req, block.map(Into::into), state_override)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn pfcall(
        &self,
        req: CallRequest,
        block: Option<BlockIdVariant>,
        state_override: Option<StateOverride>,
    ) -> RpcResult<Bytes> {
        self.call_impl(req, block.map(Into::into), state_override)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    /// Handler for: `eth_updatePFC`
    async fn update_pfc(&self, input_list: Vec<String>) -> RpcResult<bool> {
        if input_list.len() > 20 {
            return Err(self.current_method().map_err(Web3Error::InternalError(anyhow::anyhow!("The number of contracts is incorrect, the maximum number of contracts supported is 20."))));
        }      
        save_pfc_to_file(input_list).await.map_err(|e| self.current_method().map_err(Web3Error::InternalError(anyhow::anyhow!(e))))
    }

    /// 获取 PFC 映射
    async fn get_pfc(&self) -> RpcResult<std::collections::HashMap<String, String>> {
        let state_overrides = read_state_override_from_file(PFC_FILE_PATH).expect("Failed to Reading from PFC file").unwrap();
    
        let mut output_map = std::collections::HashMap::new();
        for (key, value) in state_overrides.iter() {
            output_map.insert(key.clone().to_string(), value.code.clone().unwrap().hash().to_string());
        }
    
        Ok(output_map)
    }

    async fn estimate_gas(
        &self,
        req: CallRequest,
        block: Option<BlockNumber>,
        state_override: Option<StateOverride>,
    ) -> RpcResult<U256> {
        self.estimate_gas_impl(req, block, state_override)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn gas_price(&self) -> RpcResult<U256> {
        self.gas_price_impl()
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn new_filter(&self, filter: Filter) -> RpcResult<U256> {
        self.new_filter_impl(filter)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn new_block_filter(&self) -> RpcResult<U256> {
        self.new_block_filter_impl()
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn uninstall_filter(&self, idx: U256) -> RpcResult<bool> {
        self.uninstall_filter_impl(idx)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn new_pending_transaction_filter(&self) -> RpcResult<U256> {
        self.new_pending_transaction_filter_impl()
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_logs(&self, filter: Filter) -> RpcResult<Vec<Log>> {
        self.get_logs_impl(filter)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_filter_logs(&self, filter_index: U256) -> RpcResult<FilterChanges> {
        self.get_filter_logs_impl(filter_index)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_filter_changes(&self, filter_index: U256) -> RpcResult<FilterChanges> {
        self.get_filter_changes_impl(filter_index)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_balance(
        &self,
        address: Address,
        block: Option<BlockIdVariant>,
    ) -> RpcResult<U256> {
        self.get_balance_impl(address, block.map(Into::into))
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_block_by_number(
        &self,
        block_number: BlockNumber,
        full_transactions: bool,
    ) -> RpcResult<Option<Block<TransactionVariant>>> {
        self.get_block_impl(BlockId::Number(block_number), full_transactions)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_block_by_hash(
        &self,
        hash: H256,
        full_transactions: bool,
    ) -> RpcResult<Option<Block<TransactionVariant>>> {
        self.get_block_impl(BlockId::Hash(hash), full_transactions)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_block_transaction_count_by_number(
        &self,
        block_number: BlockNumber,
    ) -> RpcResult<Option<U256>> {
        self.get_block_transaction_count_impl(BlockId::Number(block_number))
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_block_receipts(
        &self,
        block_id: BlockId,
    ) -> RpcResult<Option<Vec<TransactionReceipt>>> {
        self.get_block_receipts_impl(block_id)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_block_transaction_count_by_hash(
        &self,
        block_hash: H256,
    ) -> RpcResult<Option<U256>> {
        self.get_block_transaction_count_impl(BlockId::Hash(block_hash))
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_code(&self, address: Address, block: Option<BlockIdVariant>) -> RpcResult<Bytes> {
        self.get_code_impl(address, block.map(Into::into))
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_storage_at(
        &self,
        address: Address,
        idx: U256,
        block: Option<BlockIdVariant>,
    ) -> RpcResult<H256> {
        self.get_storage_at_impl(address, idx, block.map(Into::into))
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_transaction_count(
        &self,
        address: Address,
        block: Option<BlockIdVariant>,
    ) -> RpcResult<U256> {
        self.get_transaction_count_impl(address, block.map(Into::into))
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_transaction_by_hash(&self, hash: H256) -> RpcResult<Option<Transaction>> {
        self.get_transaction_impl(TransactionId::Hash(hash))
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_transaction_by_block_hash_and_index(
        &self,
        block_hash: H256,
        index: Index,
    ) -> RpcResult<Option<Transaction>> {
        self.get_transaction_impl(TransactionId::Block(BlockId::Hash(block_hash), index))
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_transaction_by_block_number_and_index(
        &self,
        block_number: BlockNumber,
        index: Index,
    ) -> RpcResult<Option<Transaction>> {
        self.get_transaction_impl(TransactionId::Block(BlockId::Number(block_number), index))
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn get_transaction_receipt(&self, hash: H256) -> RpcResult<Option<TransactionReceipt>> {
        self.get_transaction_receipt_impl(hash)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn protocol_version(&self) -> RpcResult<String> {
        Ok(self.protocol_version())
    }

    async fn send_raw_transaction(&self, tx_bytes: Bytes) -> RpcResult<H256> {
        self.send_raw_transaction_impl(tx_bytes)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }

    async fn syncing(&self) -> RpcResult<SyncState> {
        Ok(self.syncing_impl())
    }

    async fn accounts(&self) -> RpcResult<Vec<Address>> {
        Ok(self.accounts_impl())
    }

    async fn coinbase(&self) -> RpcResult<Address> {
        Ok(self.coinbase_impl())
    }

    async fn compilers(&self) -> RpcResult<Vec<String>> {
        Ok(self.compilers_impl())
    }

    async fn hashrate(&self) -> RpcResult<U256> {
        Ok(self.hashrate_impl())
    }

    async fn get_uncle_count_by_block_hash(&self, hash: H256) -> RpcResult<Option<U256>> {
        Ok(self.uncle_count_impl(BlockId::Hash(hash)))
    }

    async fn get_uncle_count_by_block_number(
        &self,
        number: BlockNumber,
    ) -> RpcResult<Option<U256>> {
        Ok(self.uncle_count_impl(BlockId::Number(number)))
    }

    async fn mining(&self) -> RpcResult<bool> {
        Ok(self.mining_impl())
    }

    async fn fee_history(
        &self,
        block_count: U64,
        newest_block: BlockNumber,
        reward_percentiles: Vec<f32>,
    ) -> RpcResult<FeeHistory> {
        self.fee_history_impl(block_count, newest_block, reward_percentiles)
            .await
            .map_err(|err| self.current_method().map_err(err))
    }
}
