%lang starknet

from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.math import assert_nn, assert_not_zero, assert_le
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.starknet.common.syscalls import call_contract
from src.DataTypes import Transaction, Signature, TxStatus

### STORAGE VARS ###

# store number of owners of the multisig
@storage_var
func owner_len() -> (res: felt):
end

@storage_var
func num_confirmations() -> (res: felt):
end

@storage_var
func owner_pubkeys(key: felt) -> (is_present: felt):
end

@storage_var
func owner_pubkeys_list(index: felt) -> (res: felt):
end

@storage_var
func transaction_list(index: felt) -> (res: Transaction):
end

@storage_var
func num_transactions() -> (res: felt):
end

@storage_var
func transaction_status(index: felt) -> (res: TxStatus):
end

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    pubkeys_len: felt, pubkeys:felt*, num_confirmations_: felt
):

    assert_not_zero(num_confirmations_)
    assert_le(num_confirmations_,pubkeys_len)
    owner_len.write(pubkeys_len)
    update_pubkeys(pubkeys_len,pubkeys)
    num_confirmations.write(num_confirmations_)
    return()
end

### EXTERNAL FUNCTIONS ###

@external
func add_transaction{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    transaction: Transaction):

    let (current_tx_len) = num_transactions.read()
    num_transactions.write(current_tx_len+1)
    transaction_list.write(current_tx_len,transaction)
    let tx_status: TxStatus = TxStatus(is_registered=TRUE, is_executed=FALSE)
    transaction_status.write(index, tx_status)
    return()
end

@external
func execute_transaction{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    index: felt, sig_len: felt, sig: Signature*, pubkeys_len: felt, pubkeys: felt*) -> (
    retdata_len: felt, retdata: felt*):

    assert sig_len = pubkeys_len
    let (transaction: Transaction) = transaction_list.read(index)
    assert_tx_registered_and_unexecuted(index)
    let (tx_hash) = calc_transaction_hash(index, transaction)
    let (num_required) = num_confirmations.read()
    assert_le(num_required, sig_len)
    verify_num_signatures(sig_len, sig, pubkeys, 0, tx_hash)
   

    let (retdata_len: felt, retdata: felt*) = call_contract(
        transaction.to,
        transaction.function_selector,
        transaction.calldata_len,
        transaction.calldata
    )
    update_transaction_status(index)
    return (retdata_len, retdata)
end



### INTERNAL FUNCTIONS ###

func update_pubkeys{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    pubkeys_len: felt, pubkeys: felt*):

    if pubkeys_len==0:
        return()
    end

    owner_pubkeys.write([pubkeys],TRUE)
    owner_pubkeys_list.write(pubkeys_len-1, [pubkeys])
    update_pubkeys(pubkeys_len - 1, pubkeys + 1)
    return()
end

func calc_transaction_hash{
    syscall_ptr : felt*, pedersen_ptr : HashBuiltin*,
    range_check_ptr}(index: felt, data:Transaction) -> (hash:felt):

    let hash_ptr = pedersen_ptr
    with hash_ptr:
        let (hash_state_ptr) = hash_init()
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, index)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, data.to)
        let (hash_state_ptr) = hash_update_single(hash_state_ptr, data.function_selector)
        let (hash_state_ptr) = hash_update_with_hashchain(hash_state_ptr, data.calldata, data.calldata_len)
        let (hash) = hash_finalize(hash_state_ptr)
        let pedersen_ptr = hash_ptr
        return(hash)
    end
end

func assert_tx_registered_and_unexecuted{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    index: felt):

    let (transaction: Transaction) = transaction_list.read(index)
    let (tx_status: TxStatus) = transaction_status.read(index)
    assert tx_status.is_registered=TRUE
    assert tx_status.is_executed=FALSE
    return()
end

func verify_num_signatures{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr, ecdsa_ptr: SignatureBuiltin*}(
    sig_len: felt, sig: Signature*, pubkeys: felt*, index: felt, tx_hash: felt):

    if index==sig_len:
        return ()
    end

    verify_ecdsa_signature(message = tx_hash,
                           public_key = [pubkeys],
                           signature_r = [sig].r,
                           signature_s = [sig].s)

    verify_num_signatures(sig_len, sig + Signature.SIZE, pubkeys+1, index + 1, tx_hash)
    return()
end 

func update_transaction_status{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    index: felt):

    let tx_status: TxStatus = TxStatus(is_registered=TRUE, is_executed=TRUE)
    transaction_status.write(index, tx_status)
    return()
end


