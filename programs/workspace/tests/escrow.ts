import * as anchor from "@coral-xyz/anchor";
import { BN } from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Escrow } from "../target/types/escrow";
import {
  createMint,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  getAccount,
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  TokenAccountNotFoundError,
} from "@solana/spl-token";
import { Keypair, PublicKey } from "@solana/web3.js";
import { assert } from "chai";

const TREASURY_PUBKEY = new PublicKey(
  "qw4hzfV7UUXTrNh3hiS9Q8KSPMXWUusNoyFKLvtcMMX"
);

// ============================================================================
// Helpers
// ============================================================================

function deriveEscrowPDAs(
  programId: PublicKey,
  requester: PublicKey,
  provider: PublicKey,
  conversationId: Buffer
): {
  escrowAccount: PublicKey;
  escrowVaultAuthority: PublicKey;
  escrowVault: (mint: PublicKey) => PublicKey;
} {
  const [escrowAccount] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("escrow"),
      requester.toBuffer(),
      provider.toBuffer(),
      conversationId,
    ],
    programId
  );

  const [escrowVaultAuthority] = PublicKey.findProgramAddressSync(
    [Buffer.from("escrow_vault"), escrowAccount.toBuffer()],
    programId
  );

  return {
    escrowAccount,
    escrowVaultAuthority,
    escrowVault: (mint: PublicKey) =>
      getAssociatedTokenAddressSync(mint, escrowVaultAuthority, true),
  };
}

// ============================================================================
// Suite
// ============================================================================

describe("escrow", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Escrow as Program<Escrow>;
  const conn = provider.connection;
  const payer = (provider.wallet as anchor.Wallet).payer;

  let usdcMint: PublicKey;
  let treasuryAta: PublicKey;

  // Unique conversation IDs per test to avoid PDA collisions
  let convNonce = 0;
  function nextConvId(): Buffer {
    const buf = Buffer.alloc(16);
    buf.writeUInt32LE(++convNonce, 0);
    return buf;
  }

  before(async () => {
    // Deploy a test USDC-like mint (6 decimals, mint authority = payer)
    usdcMint = await createMint(conn, payer, payer.publicKey, null, 6);

    // Pre-create treasury ATA so the program can transfer fee to it
    const treAcc = await getOrCreateAssociatedTokenAccount(
      conn,
      payer,
      usdcMint,
      TREASURY_PUBKEY,
      true // allowOwnerOffCurve — TREASURY is a regular key but treated as PDA-safe here
    );
    treasuryAta = treAcc.address;
  });

  // Fund a keypair with SOL + mint it some USDC; return keypair + its ATA.
  async function setupParty(
    amountUsdc: number
  ): Promise<{ kp: Keypair; ata: PublicKey }> {
    const kp = Keypair.generate();
    const sig = await conn.requestAirdrop(kp.publicKey, 2_000_000_000);
    const { blockhash, lastValidBlockHeight } =
      await conn.getLatestBlockhash();
    await conn.confirmTransaction({
      signature: sig,
      blockhash,
      lastValidBlockHeight,
    });

    const ataAcc = await getOrCreateAssociatedTokenAccount(
      conn,
      payer,
      usdcMint,
      kp.publicKey
    );
    if (amountUsdc > 0) {
      await mintTo(conn, payer, usdcMint, ataAcc.address, payer, amountUsdc);
    }
    return { kp, ata: ataAcc.address };
  }

  // Send a no-op airdrop to advance the slot counter by at least 1.
  async function advanceSlot(): Promise<void> {
    const sig = await conn.requestAirdrop(payer.publicKey, 1);
    const { blockhash, lastValidBlockHeight } =
      await conn.getLatestBlockhash();
    await conn.confirmTransaction({
      signature: sig,
      blockhash,
      lastValidBlockHeight,
    });
  }

  // Build the common `lockPayment` account object
  function lockAccounts(
    requester: PublicKey,
    providerPk: PublicKey,
    escrowAccount: PublicKey,
    escrowVaultAuthority: PublicKey,
    escrowVault: PublicKey,
    requesterUsdc: PublicKey
  ) {
    return {
      requester,
      provider: providerPk,
      escrowAccount,
      escrowVaultAuthority,
      escrowVault,
      requesterUsdc,
      usdcMint,
      tokenProgram: TOKEN_PROGRAM_ID,
      associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
      systemProgram: anchor.web3.SystemProgram.programId,
    };
  }

  // ── 1. Happy path: lock → approve, no notary ──────────────────────────────

  it("lock then approve payment — no notary", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    await program.methods
      .lockPayment(Array.from(convId), new BN(10_000_000), new BN(0), null, new BN(100))
      .accounts(
        lockAccounts(
          requester.kp.publicKey,
          providerParty.kp.publicKey,
          escrowAccount,
          escrowVaultAuthority,
          vault,
          requester.ata
        )
      )
      .signers([requester.kp])
      .rpc();

    const vaultBal = await getAccount(conn, vault);
    assert.equal(vaultBal.amount.toString(), "10000000", "vault holds payment");

    await program.methods
      .approvePayment()
      .accounts({
        approver: requester.kp.publicKey,
        escrowAccount,
        requester: requester.kp.publicKey,
        escrowVaultAuthority,
        escrowVault: vault,
        providerUsdc: providerParty.ata,
        treasuryUsdc: treasuryAta,
        treasury: TREASURY_PUBKEY,
        // notaryUsdc is unchecked; pass any writable account when not used
        notaryUsdc: providerParty.ata,
        usdcMint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([requester.kp])
      .rpc();

    // fee = 10_000_000 * 50 / 10_000 = 50_000
    const providerBal = await getAccount(conn, providerParty.ata);
    assert.equal(providerBal.amount.toString(), "9950000", "provider gets amount minus fee");

    const treasuryBal = await getAccount(conn, treasuryAta);
    assert.equal(treasuryBal.amount.toString(), "50000", "treasury gets protocol fee");

    // Vault ATA must be closed
    let vaultClosed = false;
    try {
      await getAccount(conn, vault);
    } catch (e) {
      if (e instanceof TokenAccountNotFoundError) vaultClosed = true;
    }
    assert.isTrue(vaultClosed, "vault ATA should be closed after settlement");
  });

  // ── 2. Happy path: lock → approve, with notary + fee ─────────────────────

  it("lock then approve payment — notary approves and collects fee", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const notaryParty = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    // Total locked = 10 USDC task + 1 USDC notary fee = 11 USDC
    await program.methods
      .lockPayment(
        Array.from(convId),
        new BN(10_000_000),
        new BN(1_000_000),
        notaryParty.kp.publicKey,
        new BN(100)
      )
      .accounts(
        lockAccounts(
          requester.kp.publicKey,
          providerParty.kp.publicKey,
          escrowAccount,
          escrowVaultAuthority,
          vault,
          requester.ata
        )
      )
      .signers([requester.kp])
      .rpc();

    // Notary approves
    await program.methods
      .approvePayment()
      .accounts({
        approver: notaryParty.kp.publicKey,
        escrowAccount,
        requester: requester.kp.publicKey,
        escrowVaultAuthority,
        escrowVault: vault,
        providerUsdc: providerParty.ata,
        treasuryUsdc: treasuryAta,
        treasury: TREASURY_PUBKEY,
        notaryUsdc: notaryParty.ata,
        usdcMint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([notaryParty.kp])
      .rpc();

    // fee = 50_000; provider = 9_950_000; notary = 1_000_000
    const providerBal = await getAccount(conn, providerParty.ata);
    assert.equal(providerBal.amount.toString(), "9950000");

    const notaryBal = await getAccount(conn, notaryParty.ata);
    assert.equal(notaryBal.amount.toString(), "1000000", "notary receives designated fee");
  });

  // ── 3. Happy path: lock → claim_timeout ──────────────────────────────────

  it("lock then claim_timeout after timeout passes", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    // timeout_slots = 1 so a single subsequent transaction puts us past it
    await program.methods
      .lockPayment(Array.from(convId), new BN(10_000_000), new BN(0), null, new BN(1))
      .accounts(
        lockAccounts(
          requester.kp.publicKey,
          providerParty.kp.publicKey,
          escrowAccount,
          escrowVaultAuthority,
          vault,
          requester.ata
        )
      )
      .signers([requester.kp])
      .rpc();

    // Advance at least one slot
    await advanceSlot();

    await program.methods
      .claimTimeout()
      .accounts({
        provider: providerParty.kp.publicKey,
        escrowAccount,
        requester: requester.kp.publicKey,
        escrowVaultAuthority,
        escrowVault: vault,
        providerUsdc: providerParty.ata,
        treasuryUsdc: treasuryAta,
        treasury: TREASURY_PUBKEY,
        usdcMint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([providerParty.kp])
      .rpc();

    // fee = 50_000; provider gets 9_950_000
    const providerBal = await getAccount(conn, providerParty.ata);
    assert.equal(providerBal.amount.toString(), "9950000");

    let vaultClosed = false;
    try {
      await getAccount(conn, vault);
    } catch (e) {
      if (e instanceof TokenAccountNotFoundError) vaultClosed = true;
    }
    assert.isTrue(vaultClosed, "vault should be closed after timeout claim");
  });

  // ── 4. Happy path: lock → cancel ─────────────────────────────────────────

  it("lock then cancel — requester reclaims full amount", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    await program.methods
      .lockPayment(Array.from(convId), new BN(10_000_000), new BN(0), null, new BN(1000))
      .accounts(
        lockAccounts(
          requester.kp.publicKey,
          providerParty.kp.publicKey,
          escrowAccount,
          escrowVaultAuthority,
          vault,
          requester.ata
        )
      )
      .signers([requester.kp])
      .rpc();

    const balBefore = await getAccount(conn, requester.ata);

    await program.methods
      .cancelEscrow()
      .accounts({
        requester: requester.kp.publicKey,
        escrowAccount,
        escrowVaultAuthority,
        escrowVault: vault,
        requesterUsdc: requester.ata,
        usdcMint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([requester.kp])
      .rpc();

    const balAfter = await getAccount(conn, requester.ata);
    assert.equal(
      Number(balAfter.amount) - Number(balBefore.amount),
      10_000_000,
      "requester gets full refund on cancel"
    );

    let vaultClosed = false;
    try {
      await getAccount(conn, vault);
    } catch (e) {
      if (e instanceof TokenAccountNotFoundError) vaultClosed = true;
    }
    assert.isTrue(vaultClosed, "vault should be closed after cancel");
  });

  // ── 5. Error: wrong approver ──────────────────────────────────────────────

  it("rejects approve from unauthorized caller", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const stranger = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    await program.methods
      .lockPayment(Array.from(convId), new BN(10_000_000), new BN(0), null, new BN(1000))
      .accounts(
        lockAccounts(
          requester.kp.publicKey,
          providerParty.kp.publicKey,
          escrowAccount,
          escrowVaultAuthority,
          vault,
          requester.ata
        )
      )
      .signers([requester.kp])
      .rpc();

    try {
      await program.methods
        .approvePayment()
        .accounts({
          approver: stranger.kp.publicKey,
          escrowAccount,
          requester: requester.kp.publicKey,
          escrowVaultAuthority,
          escrowVault: vault,
          providerUsdc: providerParty.ata,
          treasuryUsdc: treasuryAta,
          treasury: TREASURY_PUBKEY,
          notaryUsdc: providerParty.ata,
          usdcMint,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([stranger.kp])
        .rpc();
      assert.fail("Should have rejected unauthorized approver");
    } catch (e: any) {
      assert.include(e.toString(), "Unauthorized");
    }
  });

  // ── 6. Error: double settlement ───────────────────────────────────────────

  it("rejects double settlement on same escrow", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    await program.methods
      .lockPayment(Array.from(convId), new BN(10_000_000), new BN(0), null, new BN(1000))
      .accounts(
        lockAccounts(
          requester.kp.publicKey,
          providerParty.kp.publicKey,
          escrowAccount,
          escrowVaultAuthority,
          vault,
          requester.ata
        )
      )
      .signers([requester.kp])
      .rpc();

    await program.methods
      .approvePayment()
      .accounts({
        approver: requester.kp.publicKey,
        escrowAccount,
        requester: requester.kp.publicKey,
        escrowVaultAuthority,
        escrowVault: vault,
        providerUsdc: providerParty.ata,
        treasuryUsdc: treasuryAta,
        treasury: TREASURY_PUBKEY,
        notaryUsdc: providerParty.ata,
        usdcMint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([requester.kp])
      .rpc();

    // Second approve must fail — escrow_account was closed
    try {
      await program.methods
        .approvePayment()
        .accounts({
          approver: requester.kp.publicKey,
          escrowAccount,
          requester: requester.kp.publicKey,
          escrowVaultAuthority,
          escrowVault: vault,
          providerUsdc: providerParty.ata,
          treasuryUsdc: treasuryAta,
          treasury: TREASURY_PUBKEY,
          notaryUsdc: providerParty.ata,
          usdcMint,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([requester.kp])
        .rpc();
      assert.fail("Second approve should fail");
    } catch (_) {
      // Expected — account no longer exists
    }
  });

  // ── 7. Error: claim before timeout ───────────────────────────────────────

  it("rejects claim_timeout before timeout has elapsed", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    // Large timeout — provider can never claim in the test
    await program.methods
      .lockPayment(Array.from(convId), new BN(10_000_000), new BN(0), null, new BN(1_000_000))
      .accounts(
        lockAccounts(
          requester.kp.publicKey,
          providerParty.kp.publicKey,
          escrowAccount,
          escrowVaultAuthority,
          vault,
          requester.ata
        )
      )
      .signers([requester.kp])
      .rpc();

    try {
      await program.methods
        .claimTimeout()
        .accounts({
          provider: providerParty.kp.publicKey,
          escrowAccount,
          requester: requester.kp.publicKey,
          escrowVaultAuthority,
          escrowVault: vault,
          providerUsdc: providerParty.ata,
          treasuryUsdc: treasuryAta,
          treasury: TREASURY_PUBKEY,
          usdcMint,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([providerParty.kp])
        .rpc();
      assert.fail("Should have rejected premature claim");
    } catch (e: any) {
      assert.include(e.toString(), "TimeoutNotReached");
    }
  });

  // ── 8. Error: cancel after timeout ───────────────────────────────────────

  it("rejects cancel after timeout has elapsed", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    await program.methods
      .lockPayment(Array.from(convId), new BN(10_000_000), new BN(0), null, new BN(1))
      .accounts(
        lockAccounts(
          requester.kp.publicKey,
          providerParty.kp.publicKey,
          escrowAccount,
          escrowVaultAuthority,
          vault,
          requester.ata
        )
      )
      .signers([requester.kp])
      .rpc();

    // Advance past the 1-slot timeout
    await advanceSlot();

    try {
      await program.methods
        .cancelEscrow()
        .accounts({
          requester: requester.kp.publicKey,
          escrowAccount,
          escrowVaultAuthority,
          escrowVault: vault,
          requesterUsdc: requester.ata,
          usdcMint,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([requester.kp])
        .rpc();
      assert.fail("Should have rejected cancel after timeout");
    } catch (e: any) {
      assert.include(e.toString(), "TimeoutAlreadyReached");
    }
  });

  // ── 9. Error: zero amount ─────────────────────────────────────────────────

  it("rejects lock with zero amount", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    try {
      await program.methods
        .lockPayment(Array.from(convId), new BN(0), new BN(0), null, new BN(1000))
        .accounts(
          lockAccounts(
            requester.kp.publicKey,
            providerParty.kp.publicKey,
            escrowAccount,
            escrowVaultAuthority,
            vault,
            requester.ata
          )
        )
        .signers([requester.kp])
        .rpc();
      assert.fail("Should have rejected zero amount");
    } catch (e: any) {
      assert.include(e.toString(), "ZeroAmount");
    }
  });

  // ── 10. Error: notary_fee without notary ──────────────────────────────────

  it("rejects notary_fee > 0 when no notary is set", async () => {
    const requester = await setupParty(50_000_000);
    const providerParty = await setupParty(0);
    const convId = nextConvId();

    const { escrowAccount, escrowVaultAuthority, escrowVault } =
      deriveEscrowPDAs(
        program.programId,
        requester.kp.publicKey,
        providerParty.kp.publicKey,
        convId
      );
    const vault = escrowVault(usdcMint);

    try {
      await program.methods
        .lockPayment(
          Array.from(convId),
          new BN(10_000_000),
          new BN(500_000), // notary_fee > 0
          null,            // but no notary!
          new BN(1000)
        )
        .accounts(
          lockAccounts(
            requester.kp.publicKey,
            providerParty.kp.publicKey,
            escrowAccount,
            escrowVaultAuthority,
            vault,
            requester.ata
          )
        )
        .signers([requester.kp])
        .rpc();
      assert.fail("Should have rejected notary_fee without notary");
    } catch (e: any) {
      assert.include(e.toString(), "NotaryFeeWithoutNotary");
    }
  });
});
