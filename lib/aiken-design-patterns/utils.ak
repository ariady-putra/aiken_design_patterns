//// @hidden

use aiken/collection/list
use aiken/crypto.{ScriptHash}
use aiken/fuzz
use cardano/address.{Address, VerificationKey}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{NoDatum, OutputReference}
use cardano/transaction/output_reference
use test_kit/fuzzy/fuzzer.{
  asset_name_fuzzer, policy_id_fuzzer, script_hash_fuzzer, transaction_id_fuzzer,
  verification_key_hash_fuzzer,
}

pub fn sort_inputs(inputs: List<transaction.Input>) -> List<transaction.Input> {
  let
    transaction.Input(l_o_ref, _),
    transaction.Input(r_o_ref, _),
  <- list.sort(inputs)

  output_reference.compare(l_o_ref, r_o_ref)
}

/// Copied from [Fortuna](https://github.com/cardano-miners/fortuna/blob/5eeb1bc31b72252b991bbcaf836b128dca6a74b9/lib/fortuna/utils.ak#L6-L17).
pub fn resolve_output_reference(
  inputs: List<transaction.Input>,
  output_ref: OutputReference,
) -> transaction.Output {
  expect [transaction.Input { output_reference, output }, ..next] = inputs

  if output_reference == output_ref {
    output
  } else {
    next |> resolve_output_reference(output_ref)
  }
}

pub fn authentic_input_is_reproduced_unchanged(
  auth_symbol: PolicyId,
  optional_auth_name: Option<AssetName>,
  in_utxo: transaction.Output,
  out_utxo: transaction.Output,
) -> Bool {
  expect transaction.Output {
    value: in_val,
    datum: in_dat,
    address: in_addr,
    reference_script: None,
  } = in_utxo
  expect transaction.Output {
    value: out_val,
    datum: out_dat,
    address: out_addr,
    reference_script: None,
  } = out_utxo

  expect [_, (in_sym, in_name, in_quantity)] = in_val |> assets.flatten

  let name_is_authentic =
    when optional_auth_name is {
      Some(auth_name) -> in_name == auth_name
      None -> True
    }

  and {
    in_val == out_val,
    in_dat == out_dat,
    in_addr.payment_credential == out_addr.payment_credential,
    in_sym == auth_symbol,
    name_is_authentic,
    in_quantity == 1,
  }
}

pub fn sum_of_squares(xs: List<Int>) -> Int {
  let x, acc <- list.foldl(xs, 0)
  acc + x * x
}

/// Given a list of inputs, this function returns the index of the first inputs
/// which its address has a `Script` payment part.
pub fn find_index_of_first_script_input(inputs: List<transaction.Input>) -> Int {
  expect Some(input_index) = {
    let
      i,
      transaction.Input {
        output: transaction.Output {
          address: Address { payment_credential, .. },
          ..
        },
        ..
      },
      m_i,
    <- list.indexed_foldr(inputs, None)

    when m_i is {
      Some(_) -> m_i
      None ->
        when payment_credential is {
          address.Script(_) -> Some(i)
          _ -> None
        }
    }
  }

  input_index
}

/// A fuzzer for `Value` with a single asset. Unsafely expects 28 bytes long
/// policy ID to be provided.
pub fn single_specific_asset_value_fuzzer(
  policy_id: ByteArray,
) -> Fuzzer<assets.Value> {
  let
    token_name,
    quantity,
  <- fuzz.map2(asset_name_fuzzer(), fuzz.int_at_least(1))

  policy_id |> assets.from_asset(token_name, quantity)
}

/// A `Value` fuzzer with a single asset. Randomly generates the policy ID.
pub fn single_asset_value_fuzzer() -> Fuzzer<assets.Value> {
  let policy_id <- fuzz.and_then(policy_id_fuzzer())
  single_specific_asset_value_fuzzer(policy_id)
}

/// A `Value` fuzzer without any lovelaces.
pub fn mint_fuzzer() -> Fuzzer<assets.Value> {
  let other_assets_values <-
    fuzz.map(fuzz.list_between(single_asset_value_fuzzer(), 1, 10))

  let v, acc <- list.foldl(other_assets_values, assets.zero)
  assets.merge(v, acc)
}

/// A `Value` fuzzer, guaranteed to include some amount of ADA (minimum must be
/// specified).
pub fn value_fuzzer(min_lovelaces: Int) -> Fuzzer<assets.Value> {
  let lovelace_count <- fuzz.and_then(fuzz.int_at_least(min_lovelaces))
  let lovelace_value = assets.from_lovelace(lovelace_count)

  let other_assets_values <-
    fuzz.map(fuzz.list_at_most(single_asset_value_fuzzer(), 10))

  let v, acc <- list.foldl(other_assets_values, lovelace_value)
  assets.merge(v, acc)
}

/// Output reference fuzzer, transaction ID with 32 bytes, and output index
/// between 0 and 512.
pub fn output_reference_fuzzer() -> Fuzzer<OutputReference> {
  let
    ref_bytes,
    output_index,
  <- fuzz.map2(transaction_id_fuzzer(), fuzz.int_between(0, 512))

  OutputReference { transaction_id: ref_bytes, output_index }
}

/// Simple wallet UTxO fuzzer, with a random number of tokens/NFTs.
pub fn user_output_fuzzer() -> Fuzzer<transaction.Output> {
  let
    pkh,
    skh,
    v,
  <-
    fuzz.map3(
      verification_key_hash_fuzzer(),
      script_hash_fuzzer(),
      value_fuzzer(2_000_000),
    )

  transaction.Output {
    address: Address {
      payment_credential: pkh |> VerificationKey,
      stake_credential: skh |> VerificationKey |> address.Inline |> Some,
    },
    value: v,
    datum: NoDatum,
    reference_script: None,
  }
}

/// Simple wallet UTxO fuzzer, with a random reference output and a random
/// number of tokens/NFTs.
pub fn user_input_fuzzer() -> Fuzzer<transaction.Input> {
  let
    output_reference,
    output,
  <- fuzz.map2(output_reference_fuzzer(), user_output_fuzzer())

  transaction.Input { output_reference, output }
}

/// Given a script hash and datum, this fuzzer generates a UTxO at an address
/// which its payment part is the same as the given script hash.
pub fn specific_script_output_fuzzer(
  script_hash: ScriptHash,
  datum: transaction.Datum,
) -> Fuzzer<transaction.Output> {
  let v <- fuzz.map(value_fuzzer(2_000_000))
  transaction.Output {
    address: Address {
      payment_credential: address.Script(script_hash),
      stake_credential: None,
    },
    value: v,
    datum,
    reference_script: None,
  }
}

/// Returns a tuple where its first element is the random script hash (payment
/// part of the UTxO's address). UTxO value is also random, with 2 ADA.
pub fn script_output_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Output)> {
  let script_hash <- fuzz.and_then(script_hash_fuzzer())

  let utxo <- fuzz.map(specific_script_output_fuzzer(script_hash, datum))
  (script_hash, utxo)
}

/// UTxO fuzzer, where the value is composed of 2 ADA and a beacon NFT, such
/// that its policy ID is equal to the script credential of the payment part of
/// UTxO's address. This script hash is also returned.
pub fn authentic_script_output_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Output)> {
  let script_hash, tn <- fuzz.map2(script_hash_fuzzer(), asset_name_fuzzer())

  let lovelace_value = assets.from_lovelace(2_000_000)
  let beacon = assets.from_asset(script_hash, tn, 1)
  let v = assets.merge(lovelace_value, beacon)

  (
    script_hash,
    transaction.Output {
      address: Address {
        payment_credential: address.Script(script_hash),
        stake_credential: None,
      },
      value: v,
      datum,
      reference_script: None,
    },
  )
}

/// Similar to [`specific_script_output_fuzzer`](#specific_script_output_fuzzer),
/// with an additional randomized wrapper for output reference.
pub fn specific_script_input_fuzzer(
  script_hash: ScriptHash,
  datum: transaction.Datum,
) -> Fuzzer<transaction.Input> {
  let
    output_reference,
    output,
  <-
    fuzz.map2(
      output_reference_fuzzer(),
      specific_script_output_fuzzer(script_hash, datum),
    )

  transaction.Input { output_reference, output }
}

/// Similar to [`script_output_fuzzer`](#script_output_fuzzer), with an
/// additional randomized wrapper for output reference.
pub fn script_input_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Input)> {
  let
    output_reference,
    (script_hash, output),
  <- fuzz.map2(output_reference_fuzzer(), script_output_fuzzer(datum))

  (script_hash, transaction.Input { output_reference, output })
}

/// Similar to [`authentic_script_output_fuzzer`](#script_output_fuzzer), with
/// and additional randomized wrapper for output reference.
pub fn authentic_script_input_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Input)> {
  let
    output_reference,
    (script_hash, output),
  <- fuzz.map2(output_reference_fuzzer(), authentic_script_output_fuzzer(datum))

  (script_hash, transaction.Input { output_reference, output })
}

/// Simple (non-script) outputs fuzzer.
pub fn user_outputs_fuzzer() -> Fuzzer<List<transaction.Output>> {
  fuzz.list_between(user_output_fuzzer(), 1, 10)
}

/// Simple (non-script) inputs fuzzer.
pub fn user_inputs_fuzzer() -> Fuzzer<List<transaction.Input>> {
  fuzz.list_between(user_input_fuzzer(), 1, 10)
}

/// Fuzzer for a sorted list of user/wallet inputs, with the addition of one
/// authentic script input.
pub fn inputs_with_an_authentic_script_input_fuzzer(
  datum: transaction.Datum,
) -> Fuzzer<(ScriptHash, transaction.Input, List<transaction.Input>)> {
  let
    wallet_inputs,
    (spend_script_hash, script_input),
  <- fuzz.map2(user_inputs_fuzzer(), authentic_script_input_fuzzer(datum))

  (
    spend_script_hash,
    script_input,
    [script_input, ..wallet_inputs] |> sort_inputs,
  )
}
