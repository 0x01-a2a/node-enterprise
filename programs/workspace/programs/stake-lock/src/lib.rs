use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, CloseAccount, Mint, Token, TokenAccount, Transfer},
    token_interface::{
        Mint as MintInterface, TokenAccount as TokenAccountInterface, TokenInterface,
    },
};

declare_id!("Dvf1qPzzvW1BkSUogRMaAvxZpXrmeTqYutTCBKpzHB1A");

// ============================================================================
// StakeLock Program (doc 5, §10.5)
//
// Holds the minimum stake for each 0x01 agent, denominated in USDC.
// Stake is separate from SATI registration — SATI itself does not hold stake.
//
// Accounts use a payer/owner split to support Kora gasless transactions:
//   payer = transaction fee payer (Kora's pubkey when using gasless path)
//   owner = agent wallet (signs USDC transfer from their ATA)
// When not using Kora: payer == owner.
//
// Only the Challenge program can slash via its on-chain program ID check.
// ============================================================================

/// 10 USDC minimum stake (6 decimal places — USDC on Solana has 6 decimals).
pub const MIN_STAKE_USDC: u64 = 10_000_000;
/// ~2 days at 400ms/slot before stake can be claimed after unlock queue.
pub const UNLOCK_DELAY_SLOTS: u64 = 432_000;
/// Challenge program ID — only this program can call slash().
const CHALLENGE_PROGRAM_ID: Pubkey = pubkey!("7FoisCiS1gyUx7osQkCLk4A1zNKGq37yHpVhL2BFgk1Y");
/// Lease program ID — used to verify lease PDA in queue_unlock.
const LEASE_PROGRAM_ID: Pubkey = pubkey!("5P8uXqavnQFGXbHKE3tQDezh41D7ZutHsT2jY6gZ3C3x");
/// BehaviorLog program ID — AgentBatchRegistry accounts must be owned by this.
const BEHAVIOR_LOG_PROGRAM_ID: Pubkey = pubkey!("35DAMPQVu6wsmMEGv67URFAGgyauEYD73egd74uiX1sM");
/// USDC mint address — constrain all token operations to real USDC.
#[cfg(feature = "devnet")]
pub const USDC_MINT: Pubkey = pubkey!("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
#[cfg(not(feature = "devnet"))]
pub const USDC_MINT: Pubkey = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
/// 0x01 genesis Unix timestamp. March 1, 2026.
pub const GENESIS_TIMESTAMP: i64 = 1_772_313_600;
/// Epoch length in seconds (1 day).
pub const EPOCH_SECONDS: u64 = 86_400;
/// Grace period in epochs before an inactive agent can be slashed.
pub const INACTIVITY_GRACE_EPOCHS: u64 = 3;
/// AgentBatchRegistry raw byte offset for the next_epoch field.
/// Layout: 8 (disc) + 1 (version) + 32 (agent_id) = 41 → next_epoch (u64)
const REGISTRY_NEXT_EPOCH_OFFSET: usize = 41;
const REGISTRY_MIN_LEN: usize = 50; // 8 + 1 + 32 + 8 + 1

#[program]
pub mod stake_lock {
    use super::*;

    /// Lock MIN_STAKE_USDC for a newly registered agent.
    ///
    /// Caller must own the SATI Token-2022 NFT for agent_mint.
    /// Requires SATI AgentIndex PDA to exist (proves registration is complete).
    pub fn lock_stake(ctx: Context<LockStake>, args: LockStakeArgs) -> Result<()> {
        let stake = &mut ctx.accounts.stake_account;
        let clock = Clock::get()?;

        require!(
            args.amount >= MIN_STAKE_USDC,
            StakeLockError::InsufficientStake
        );
        require!(
            args.agent_mint == ctx.accounts.agent_mint_account.key().to_bytes(),
            StakeLockError::MintMismatch
        );

        // Transfer USDC from owner's ATA to stake vault.
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.owner_usdc.to_account_info(),
                to: ctx.accounts.stake_vault.to_account_info(),
                authority: ctx.accounts.owner.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, args.amount)?;

        stake.version = 1;
        stake.agent_mint = args.agent_mint;
        stake.owner = ctx.accounts.owner.key();
        stake.stake_usdc = args.amount;
        stake.locked_since_slot = clock.slot;
        stake.in_unlock_queue = false;
        stake.unlock_available_slot = 0;
        stake.bump = ctx.bumps.stake_account;
        stake.vault_authority_bump = ctx.bumps.stake_vault_authority;

        emit!(StakeLocked {
            agent_mint: args.agent_mint,
            owner: ctx.accounts.owner.key(),
            usdc: args.amount,
            slot: clock.slot,
        });

        Ok(())
    }

    /// Lock MIN_STAKE_USDC for an 8004 registered agent.
    /// Does not require a SATI NFT. The agent (owner) signs directly.
    pub fn lock_stake_8004(ctx: Context<LockStake8004>, args: LockStakeArgs) -> Result<()> {
        let stake = &mut ctx.accounts.stake_account;
        let clock = Clock::get()?;

        require!(
            args.amount >= MIN_STAKE_USDC,
            StakeLockError::InsufficientStake
        );
        require!(
            args.agent_mint == ctx.accounts.owner.key().to_bytes(),
            StakeLockError::MintMismatch
        );

        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.owner_usdc.to_account_info(),
                to: ctx.accounts.stake_vault.to_account_info(),
                authority: ctx.accounts.owner.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, args.amount)?;

        stake.version = 1;
        stake.agent_mint = args.agent_mint;
        stake.owner = ctx.accounts.owner.key();
        stake.stake_usdc = args.amount;
        stake.locked_since_slot = clock.slot;
        stake.in_unlock_queue = false;
        stake.unlock_available_slot = 0;
        stake.bump = ctx.bumps.stake_account;
        stake.vault_authority_bump = ctx.bumps.stake_vault_authority;

        emit!(StakeLocked {
            agent_mint: args.agent_mint,
            owner: ctx.accounts.owner.key(),
            usdc: args.amount,
            slot: clock.slot,
        });

        Ok(())
    }

    /// Queue stake for unlock. Only callable when the agent's lease has expired.
    ///
    /// Sets unlock_available_slot = current_slot + UNLOCK_DELAY_SLOTS.
    /// Agent must be deactivated on the Lease program before queuing.
    pub fn queue_unlock(ctx: Context<QueueUnlock>) -> Result<()> {
        let stake = &mut ctx.accounts.stake_account;
        let clock = Clock::get()?;

        // Read `deactivated` from LeaseAccount raw bytes.
        // Layout (after 8-byte discriminator): agent_id[32], owner[32],
        // paid_through_epoch[8], last_paid_slot[8], current_epoch[8],
        // in_grace_period[1], deactivated[1]  => offset 98.
        {
            let data = ctx.accounts.lease_account.try_borrow_data()?;
            require!(data.len() > 98, StakeLockError::AgentNotDeactivated);
            require!(
                ctx.accounts.lease_account.owner == &LEASE_PROGRAM_ID,
                StakeLockError::InvalidLeaseAccount
            );

            let (expected_lease, _) = Pubkey::find_program_address(
                &[b"lease", stake.agent_mint.as_ref()],
                &LEASE_PROGRAM_ID,
            );
            require!(
                ctx.accounts.lease_account.key() == expected_lease,
                StakeLockError::InvalidLeaseAccount
            );

            let deactivated = data[98] != 0;
            require!(deactivated, StakeLockError::AgentNotDeactivated);
        }
        require!(!stake.in_unlock_queue, StakeLockError::AlreadyQueued);

        stake.in_unlock_queue = true;
        stake.unlock_available_slot = clock.slot + UNLOCK_DELAY_SLOTS;

        emit!(UnlockQueued {
            agent_mint: stake.agent_mint,
            unlock_available_slot: stake.unlock_available_slot,
        });

        Ok(())
    }

    /// Claim locked stake after unlock delay has passed.
    ///
    /// Returns USDC to owner's ATA and closes the vault token account.
    pub fn claim_stake(ctx: Context<ClaimStake>) -> Result<()> {
        let stake = &ctx.accounts.stake_account;
        let clock = Clock::get()?;

        require!(stake.in_unlock_queue, StakeLockError::NotQueued);
        require!(
            clock.slot >= stake.unlock_available_slot,
            StakeLockError::UnlockDelayNotPassed,
        );

        let agent_mint = stake.agent_mint;
        let owner = stake.owner;
        let amount = ctx.accounts.stake_vault.amount;
        let vault_authority_bump = stake.vault_authority_bump;

        let signer_seeds: &[&[&[u8]]] =
            &[&[b"stake_vault", agent_mint.as_ref(), &[vault_authority_bump]]];

        // Return USDC from vault to owner.
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.stake_vault.to_account_info(),
                to: ctx.accounts.owner_usdc.to_account_info(),
                authority: ctx.accounts.stake_vault_authority.to_account_info(),
            },
            signer_seeds,
        );
        token::transfer(cpi_ctx, amount)?;

        // Close the vault token account — rent refund to owner.
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.stake_vault.to_account_info(),
                destination: ctx.accounts.owner.to_account_info(),
                authority: ctx.accounts.stake_vault_authority.to_account_info(),
            },
            signer_seeds,
        );
        token::close_account(cpi_ctx)?;

        emit!(StakeClaimed {
            agent_mint,
            owner,
            usdc: amount,
        });

        Ok(())
    }

    /// Slash stake for agent inactivity. Permissionless — any node can call.
    ///
    /// Verifies that the agent's last submitted epoch (from BehaviorLog's
    /// AgentBatchRegistry PDA) is more than INACTIVITY_GRACE_EPOCHS behind the
    /// current 0x01 epoch. Slashes 50% of locked stake and pays the bounty to
    /// the caller. Idempotent: once slashed, the inactive_slashed flag is set
    /// and subsequent calls fail.
    pub fn slash_inactive(ctx: Context<SlashInactive>) -> Result<()> {
        let clock = Clock::get()?;

        // Compute current 0x01 epoch from on-chain clock.
        let current_epoch = if clock.unix_timestamp >= GENESIS_TIMESTAMP {
            ((clock.unix_timestamp - GENESIS_TIMESTAMP) as u64) / EPOCH_SECONDS
        } else {
            0
        };

        // Verify the agent_registry is the correct PDA for this stake account's
        // agent_mint under the BehaviorLog program.
        let (expected_registry, _) = Pubkey::find_program_address(
            &[
                b"agent_registry",
                ctx.accounts.stake_account.agent_mint.as_ref(),
            ],
            &BEHAVIOR_LOG_PROGRAM_ID,
        );
        require!(
            ctx.accounts.agent_registry.key() == expected_registry,
            StakeLockError::InvalidRegistryAccount,
        );

        // Read next_epoch from AgentBatchRegistry raw bytes.
        // If the account doesn't exist (agent never submitted), treat next_epoch = 0.
        let next_epoch = {
            let data = ctx.accounts.agent_registry.try_borrow_data()?;
            if data.len() >= REGISTRY_MIN_LEN {
                require!(
                    ctx.accounts.agent_registry.owner == &BEHAVIOR_LOG_PROGRAM_ID,
                    StakeLockError::InvalidRegistryAccount,
                );
                u64::from_le_bytes(
                    data[REGISTRY_NEXT_EPOCH_OFFSET..REGISTRY_NEXT_EPOCH_OFFSET + 8]
                        .try_into()
                        .unwrap(),
                )
            } else {
                0u64
            }
        };

        require!(
            current_epoch > next_epoch + INACTIVITY_GRACE_EPOCHS,
            StakeLockError::AgentNotInactive,
        );

        let stake = &mut ctx.accounts.stake_account;
        require!(
            !stake.inactive_slashed,
            StakeLockError::AlreadySlashedInactive
        );
        require!(
            stake.stake_usdc > 0,
            StakeLockError::InsufficientStakeToSlash
        );

        stake.inactive_slashed = true;
        let slash_amount = stake.stake_usdc / 2;
        stake.stake_usdc -= slash_amount;

        let agent_mint = stake.agent_mint;
        let vault_authority_bump = stake.vault_authority_bump;
        let epoch = current_epoch;

        let signer_seeds: &[&[&[u8]]] =
            &[&[b"stake_vault", agent_mint.as_ref(), &[vault_authority_bump]]];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.stake_vault.to_account_info(),
                to: ctx.accounts.caller_usdc.to_account_info(),
                authority: ctx.accounts.stake_vault_authority.to_account_info(),
            },
            signer_seeds,
        );
        token::transfer(cpi_ctx, slash_amount)?;

        emit!(StakeSlashedInactive {
            agent_mint,
            amount: slash_amount,
            caller: ctx.accounts.caller.key(),
            epoch,
        });

        Ok(())
    }

    /// Top up stake to meet a higher required amount (GAP-08: dynamic stake).
    ///
    /// Called by an agent when the aggregator indicates their required stake
    /// has increased due to a rising anomaly score.  Transfers `amount` USDC
    /// from owner_usdc to the stake vault and increments stake_usdc.
    pub fn top_up_stake(ctx: Context<TopUpStake>, amount: u64) -> Result<()> {
        require!(amount > 0, StakeLockError::InsufficientStake);

        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.owner_usdc.to_account_info(),
                to: ctx.accounts.stake_vault.to_account_info(),
                authority: ctx.accounts.owner.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, amount)?;

        ctx.accounts.stake_account.stake_usdc = ctx
            .accounts
            .stake_account
            .stake_usdc
            .checked_add(amount)
            .ok_or(StakeLockError::Overflow)?;

        emit!(StakeToppedUp {
            agent_mint: ctx.accounts.stake_account.agent_mint,
            owner: ctx.accounts.owner.key(),
            amount,
            new_total: ctx.accounts.stake_account.stake_usdc,
        });

        Ok(())
    }

    /// Slash stake. Only callable by the Challenge program (ID enforced on-chain).
    ///
    /// Transfers `args.amount` USDC from stake vault to `recipient_usdc`.
    pub fn slash(ctx: Context<Slash>, args: SlashArgs) -> Result<()> {
        // Enforce that the caller is the Challenge program via its PDA authority.
        let (expected_auth, _) =
            Pubkey::find_program_address(&[b"slash_authority"], &CHALLENGE_PROGRAM_ID);
        require!(
            ctx.accounts.challenge_authority.key() == expected_auth,
            StakeLockError::UnauthorizedCaller,
        );

        let stake = &mut ctx.accounts.stake_account;
        let agent_mint = stake.agent_mint;
        let vault_authority_bump = stake.vault_authority_bump;

        require!(
            args.amount <= stake.stake_usdc,
            StakeLockError::InsufficientStakeToSlash,
        );
        require!(
            ctx.accounts.recipient_usdc.mint == ctx.accounts.usdc_mint.key(),
            StakeLockError::InvalidRecipientMint,
        );

        stake.stake_usdc -= args.amount;

        let signer_seeds: &[&[&[u8]]] =
            &[&[b"stake_vault", agent_mint.as_ref(), &[vault_authority_bump]]];

        // Transfer USDC from vault to recipient.
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.stake_vault.to_account_info(),
                to: ctx.accounts.recipient_usdc.to_account_info(),
                authority: ctx.accounts.stake_vault_authority.to_account_info(),
            },
            signer_seeds,
        );
        token::transfer(cpi_ctx, args.amount)?;

        emit!(StakeSlashed {
            agent_mint,
            amount: args.amount,
            recipient: ctx.accounts.recipient_usdc.key(),
        });

        Ok(())
    }
}

// ============================================================================
// Accounts
// ============================================================================

#[derive(Accounts)]
#[instruction(args: LockStakeArgs)]
pub struct LockStake<'info> {
    /// Transaction fee payer — Kora's pubkey (gasless) or same as owner.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Agent wallet — authorises USDC transfer from owner_usdc.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// Owner's USDC ATA (source of stake).
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = owner,
    )]
    pub owner_usdc: Box<Account<'info, TokenAccount>>,

    /// Stake state PDA. seeds = ["stake", agent_mint]
    #[account(
        init,
        payer = payer,
        space = StakeLockAccount::SIZE,
        seeds = [b"stake", args.agent_mint.as_ref()],
        bump
    )]
    pub stake_account: Box<Account<'info, StakeLockAccount>>,

    /// Vault authority PDA — owns the vault token account.
    /// seeds = ["stake_vault", agent_mint]
    /// CHECK: PDA used as token account authority only; holds no data.
    #[account(
        seeds = [b"stake_vault", args.agent_mint.as_ref()],
        bump
    )]
    pub stake_vault_authority: UncheckedAccount<'info>,

    /// Vault ATA — holds USDC stake.
    #[account(
        init,
        payer = payer,
        associated_token::mint      = usdc_mint,
        associated_token::authority = stake_vault_authority,
    )]
    pub stake_vault: Box<Account<'info, TokenAccount>>,

    /// The agent's SATI NFT mint (Token-2022).
    pub agent_mint_account: InterfaceAccount<'info, MintInterface>,

    /// The owner's token account for the SATI NFT, proving they own the agent.
    #[account(
        token::mint = agent_mint_account,
        token::authority = owner,
        token::token_program = sati_token_program,
        constraint = owner_sati_token.amount == 1 @ StakeLockError::NotOwner,
    )]
    pub owner_sati_token: Box<InterfaceAccount<'info, TokenAccountInterface>>,

    /// Token program for SATI NFTs (Token-2022).
    pub sati_token_program: Interface<'info, TokenInterface>,
    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(args: LockStakeArgs)]
pub struct LockStake8004<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = owner,
    )]
    pub owner_usdc: Box<Account<'info, TokenAccount>>,

    #[account(
        init,
        payer = payer,
        space = StakeLockAccount::SIZE,
        seeds = [b"stake", args.agent_mint.as_ref()],
        bump
    )]
    pub stake_account: Box<Account<'info, StakeLockAccount>>,

    /// CHECK: PDA used as token account authority only; holds no data.
    #[account(
        seeds = [b"stake_vault", args.agent_mint.as_ref()],
        bump
    )]
    pub stake_vault_authority: UncheckedAccount<'info>,

    #[account(
        init,
        payer = payer,
        associated_token::mint      = usdc_mint,
        associated_token::authority = stake_vault_authority,
    )]
    pub stake_vault: Box<Account<'info, TokenAccount>>,

    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct QueueUnlock<'info> {
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [b"stake", stake_account.agent_mint.as_ref()],
        bump  = stake_account.bump,
        constraint = stake_account.owner == owner.key() @ StakeLockError::NotOwner,
    )]
    pub stake_account: Account<'info, StakeLockAccount>,

    /// Lease account for this agent — must show deactivated = true.
    /// CHECK: We read the `deactivated` byte at offset 97 in the handler.
    pub lease_account: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ClaimStake<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    /// Owner's USDC ATA — receives returned stake.
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = owner,
    )]
    pub owner_usdc: Account<'info, TokenAccount>,

    #[account(
        mut,
        close = owner,
        seeds = [b"stake", stake_account.agent_mint.as_ref()],
        bump  = stake_account.bump,
        constraint = stake_account.owner == owner.key() @ StakeLockError::NotOwner,
    )]
    pub stake_account: Account<'info, StakeLockAccount>,

    /// CHECK: PDA authority for vault ATA.
    #[account(
        seeds = [b"stake_vault", stake_account.agent_mint.as_ref()],
        bump  = stake_account.vault_authority_bump,
    )]
    pub stake_vault_authority: UncheckedAccount<'info>,

    /// Vault ATA — USDC transferred out then account closed.
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = stake_vault_authority,
    )]
    pub stake_vault: Account<'info, TokenAccount>,

    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct SlashInactive<'info> {
    /// Caller — receives the slash bounty.
    #[account(mut)]
    pub caller: Signer<'info>,

    /// Caller's USDC ATA — receives slash bounty.
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = caller,
    )]
    pub caller_usdc: Box<Account<'info, TokenAccount>>,

    /// Stake account for the inactive agent.
    #[account(
        mut,
        seeds = [b"stake", stake_account.agent_mint.as_ref()],
        bump  = stake_account.bump,
    )]
    pub stake_account: Box<Account<'info, StakeLockAccount>>,

    /// CHECK: PDA authority for vault ATA.
    #[account(
        seeds = [b"stake_vault", stake_account.agent_mint.as_ref()],
        bump  = stake_account.vault_authority_bump,
    )]
    pub stake_vault_authority: UncheckedAccount<'info>,

    /// Vault ATA — USDC transferred to caller on slash.
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = stake_vault_authority,
    )]
    pub stake_vault: Box<Account<'info, TokenAccount>>,

    /// AgentBatchRegistry PDA from BehaviorLog — may be uninitialized.
    /// PDA seeds = ["agent_registry", agent_mint] under BehaviorLog program.
    /// CHECK: Owner and PDA seeds verified in handler.
    pub agent_registry: UncheckedAccount<'info>,

    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct TopUpStake<'info> {
    /// Agent wallet — authorises USDC transfer from owner_usdc.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// Owner's USDC ATA (source of additional stake).
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = owner,
    )]
    pub owner_usdc: Account<'info, TokenAccount>,

    /// Existing stake account for this agent.
    #[account(
        mut,
        seeds = [b"stake", stake_account.agent_mint.as_ref()],
        bump  = stake_account.bump,
        constraint = stake_account.owner == owner.key() @ StakeLockError::NotOwner,
    )]
    pub stake_account: Account<'info, StakeLockAccount>,

    /// CHECK: PDA authority for vault ATA.
    #[account(
        seeds = [b"stake_vault", stake_account.agent_mint.as_ref()],
        bump  = stake_account.vault_authority_bump,
    )]
    pub stake_vault_authority: UncheckedAccount<'info>,

    /// Vault ATA — receives additional USDC.
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = stake_vault_authority,
    )]
    pub stake_vault: Account<'info, TokenAccount>,

    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct Slash<'info> {
    /// Must be the Challenge program's PDA authority.
    /// CHECK: PDA verified in handler against CHALLENGE_PROGRAM_ID.
    pub challenge_authority: Signer<'info>,

    #[account(
        mut,
        seeds = [b"stake", stake_account.agent_mint.as_ref()],
        bump  = stake_account.bump,
    )]
    pub stake_account: Account<'info, StakeLockAccount>,

    /// CHECK: PDA authority for vault ATA.
    #[account(
        seeds = [b"stake_vault", stake_account.agent_mint.as_ref()],
        bump  = stake_account.vault_authority_bump,
    )]
    pub stake_vault_authority: UncheckedAccount<'info>,

    /// Vault ATA — USDC transferred to recipient on slash.
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = stake_vault_authority,
    )]
    pub stake_vault: Account<'info, TokenAccount>,

    /// Recipient USDC token account — challenger or treasury.
    #[account(mut)]
    pub recipient_usdc: Account<'info, TokenAccount>,

    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}

// ============================================================================
// State
// ============================================================================

/// PDA: seeds = ["stake", agent_mint]
#[account]
pub struct StakeLockAccount {
    /// Struct version for migration safety.
    pub version: u8,
    /// SATI mint address = agent ID.
    pub agent_mint: [u8; 32],
    /// Wallet that owns the SATI NFT.
    pub owner: Pubkey,
    /// Locked USDC (micro-USDC, 6 decimals).
    pub stake_usdc: u64,
    /// Slot at which stake was locked.
    pub locked_since_slot: u64,
    /// True if unlock has been queued.
    pub in_unlock_queue: bool,
    /// Earliest slot at which claim_stake can be called (0 = not queued).
    pub unlock_available_slot: u64,
    /// PDA bump.
    pub bump: u8,
    /// Vault authority PDA bump (for USDC transfer signing).
    pub vault_authority_bump: u8,
    /// Set to true after slash_inactive is called. Prevents double-slash.
    pub inactive_slashed: bool,
}

impl StakeLockAccount {
    /// 8 + 1 + 32 + 32 + 8 + 8 + 1 + 8 + 1 + 1 + 1 = 101 bytes
    pub const SIZE: usize = 8 + 1 + 32 + 32 + 8 + 8 + 1 + 8 + 1 + 1 + 1;
}

// ============================================================================
// Instruction arguments
// ============================================================================

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct LockStakeArgs {
    pub agent_mint: [u8; 32],
    pub amount: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SlashArgs {
    pub amount: u64,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct StakeLocked {
    pub agent_mint: [u8; 32],
    pub owner: Pubkey,
    pub usdc: u64,
    pub slot: u64,
}

#[event]
pub struct UnlockQueued {
    pub agent_mint: [u8; 32],
    pub unlock_available_slot: u64,
}

#[event]
pub struct StakeClaimed {
    pub agent_mint: [u8; 32],
    pub owner: Pubkey,
    pub usdc: u64,
}

#[event]
pub struct StakeSlashed {
    pub agent_mint: [u8; 32],
    pub amount: u64,
    pub recipient: Pubkey,
}

#[event]
pub struct StakeToppedUp {
    pub agent_mint: [u8; 32],
    pub owner: Pubkey,
    pub amount: u64,
    pub new_total: u64,
}

#[event]
pub struct StakeSlashedInactive {
    pub agent_mint: [u8; 32],
    pub amount: u64,
    pub caller: Pubkey,
    pub epoch: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum StakeLockError {
    #[msg("Stake amount below MIN_STAKE_USDC (10 USDC)")]
    InsufficientStake,
    #[msg("Agent must be deactivated on Lease program before unlocking")]
    AgentNotDeactivated,
    #[msg("Unlock already queued")]
    AlreadyQueued,
    #[msg("Unlock not queued — call queue_unlock first")]
    NotQueued,
    #[msg("Unlock delay has not passed yet")]
    UnlockDelayNotPassed,
    #[msg("Not enough stake to slash")]
    InsufficientStakeToSlash,
    #[msg("Agent must be registered in SATI before locking stake")]
    SatiNotRegistered,
    #[msg("Caller is not the agent owner")]
    NotOwner,
    #[msg("Caller is not the Challenge program — slash is CPI-only")]
    UnauthorizedCaller,
    #[msg("Agent is not yet inactive — inactivity grace period has not passed")]
    AgentNotInactive,
    #[msg("Agent has already been slashed for inactivity")]
    AlreadySlashedInactive,
    #[msg("Agent registry account is invalid or owned by the wrong program")]
    InvalidRegistryAccount,
    #[msg("Lease account is invalid, derived incorrectly, or owned by the wrong program")]
    InvalidLeaseAccount,
    #[msg("Agent mint argument does not match provided SATI mint account")]
    MintMismatch,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("recipient_usdc mint must match usdc_mint")]
    InvalidRecipientMint,
}
