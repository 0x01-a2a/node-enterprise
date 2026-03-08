use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Mint, Token, TokenAccount, Transfer},
    token_interface::{
        Mint as MintInterface, TokenAccount as TokenAccountInterface, TokenInterface,
    },
};

declare_id!("5P8uXqavnQFGXbHKE3tQDezh41D7ZutHsT2jY6gZ3C3x");

/// Protocol treasury wallet — receives all lease fees.
/// Replace with the actual treasury pubkey before mainnet deploy.
pub const TREASURY_PUBKEY: Pubkey = pubkey!("qw4hzfV7UUXTrNh3hiS9Q8KSPMXWUusNoyFKLvtcMMX");
/// Canonical USDC mint enforced by all lease flows.
#[cfg(feature = "devnet")]
pub const USDC_MINT: Pubkey = pubkey!("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
#[cfg(not(feature = "devnet"))]
pub const USDC_MINT: Pubkey = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

// ============================================================================
// Lease Program (doc 5, §10.3)
//
// Protocol tax denominated in USDC (doc 5, §4.4).
// Agents pre-pay daily lease fees to remain active on the mesh.
//
// Accounts use a payer/owner split to support Kora gasless transactions:
//   payer = transaction fee payer (Kora's pubkey when using gasless path)
//   owner = agent wallet (signs USDC transfer from their ATA)
// When not using Kora: payer == owner == agent wallet.
// ============================================================================

/// 1 USDC per epoch (6 decimal places — USDC on Solana has 6 decimals).
pub const LEASE_COST_PER_EPOCH_USDC: u64 = 1_000_000;
/// 3 epochs grace before deactivation.
pub const GRACE_PERIOD_EPOCHS: u64 = 3;
/// 0x01 epoch length in seconds.
pub const EPOCH_LENGTH_SECS: u64 = 86_400;

#[program]
pub mod lease {
    use super::*;

    /// Initialize a lease account for a newly registered agent.
    /// Called once after SATI registration + StakeLock.
    /// Transfers 1 epoch of USDC as the initial payment.
    pub fn init_lease(ctx: Context<InitLease>, args: InitLeaseArgs) -> Result<()> {
        let lease = &mut ctx.accounts.lease_account;
        let clock = Clock::get()?;

        require!(
            args.agent_id == ctx.accounts.agent_mint.key().to_bytes(),
            LeaseError::MintMismatch
        );

        let current_epoch = clock.unix_timestamp as u64 / EPOCH_LENGTH_SECS;

        lease.version = 1;
        lease.agent_id = args.agent_id;
        lease.owner = ctx.accounts.owner.key();
        lease.paid_through_epoch = current_epoch + 1;
        lease.last_paid_slot = clock.slot;
        lease.current_epoch = current_epoch;
        lease.in_grace_period = false;
        lease.deactivated = false;
        lease.bump = ctx.bumps.lease_account;

        // Transfer 1 epoch of USDC from owner's ATA to protocol treasury.
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.owner_usdc.to_account_info(),
                to: ctx.accounts.treasury_usdc.to_account_info(),
                authority: ctx.accounts.owner.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, LEASE_COST_PER_EPOCH_USDC)?;

        emit!(LeaseInitialized {
            agent_id: args.agent_id,
            owner: ctx.accounts.owner.key(),
            slot: clock.slot,
        });

        Ok(())
    }

    /// Initialize a lease account for an 8004 registered agent.
    /// Does not require a SATI NFT. The agent (owner) signs directly.
    pub fn init_lease_8004(ctx: Context<InitLease8004>, args: InitLeaseArgs) -> Result<()> {
        let lease = &mut ctx.accounts.lease_account;
        let clock = Clock::get()?;

        let current_epoch = clock.unix_timestamp as u64 / EPOCH_LENGTH_SECS;

        lease.version = 1;
        lease.agent_id = args.agent_id;

        // 8004 agents use their own pubkey bytes as their agent_id.
        require!(
            args.agent_id == ctx.accounts.owner.key().to_bytes(),
            LeaseError::MintMismatch
        );

        lease.owner = ctx.accounts.owner.key();
        lease.paid_through_epoch = current_epoch + 1;
        lease.last_paid_slot = clock.slot;
        lease.current_epoch = current_epoch;
        lease.in_grace_period = false;
        lease.deactivated = false;
        lease.bump = ctx.bumps.lease_account;

        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.owner_usdc.to_account_info(),
                to: ctx.accounts.treasury_usdc.to_account_info(),
                authority: ctx.accounts.owner.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, LEASE_COST_PER_EPOCH_USDC)?;

        emit!(LeaseInitialized {
            agent_id: args.agent_id,
            owner: ctx.accounts.owner.key(),
            slot: clock.slot,
        });

        Ok(())
    }

    /// Pay lease for N epochs in advance.
    ///
    /// Transfers LEASE_COST_PER_EPOCH_USDC × n_epochs from owner's USDC ATA
    /// to the lease vault, extending paid_through_epoch.
    pub fn pay_lease(ctx: Context<PayLease>, args: PayLeaseArgs) -> Result<()> {
        let lease = &mut ctx.accounts.lease_account;
        let clock = Clock::get()?;

        require!(!lease.deactivated, LeaseError::AgentDeactivated);
        require!(args.n_epochs > 0, LeaseError::ZeroEpochs);

        let total_cost = LEASE_COST_PER_EPOCH_USDC
            .checked_mul(args.n_epochs)
            .ok_or(LeaseError::Overflow)?;

        // Transfer USDC from owner's ATA to protocol treasury.
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.owner_usdc.to_account_info(),
                to: ctx.accounts.treasury_usdc.to_account_info(),
                authority: ctx.accounts.owner.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, total_cost)?;

        lease.paid_through_epoch += args.n_epochs;
        lease.last_paid_slot = clock.slot;

        // Clear grace period if they paid back up.
        if lease.in_grace_period && lease.paid_through_epoch > lease.current_epoch {
            lease.in_grace_period = false;
        }

        for i in 0..args.n_epochs {
            emit!(LeasePaid {
                agent_id: lease.agent_id,
                epoch: lease.paid_through_epoch - args.n_epochs + i,
                slot: clock.slot,
            });
        }

        Ok(())
    }

    /// Permissionless enforcement: advance lease to grace period or deactivation.
    ///
    /// Anyone can call this — there is no owner check. Ensures deactivation
    /// happens even if the owner abandons the agent.
    pub fn tick_lease(ctx: Context<TickLease>) -> Result<()> {
        let lease = &mut ctx.accounts.lease_account;
        let clock = Clock::get()?;

        let current_epoch = clock.unix_timestamp as u64 / EPOCH_LENGTH_SECS;
        lease.current_epoch = current_epoch;

        if lease.deactivated {
            return Ok(());
        }

        if current_epoch <= lease.paid_through_epoch {
            return Ok(());
        }

        let epochs_behind = current_epoch - lease.paid_through_epoch;

        if epochs_behind > GRACE_PERIOD_EPOCHS {
            lease.deactivated = true;
            lease.in_grace_period = false;
            emit!(LeaseExpired {
                agent_id: lease.agent_id,
                epoch: current_epoch
            });
        } else if !lease.in_grace_period {
            lease.in_grace_period = true;
            emit!(GracePeriodEntered {
                agent_id: lease.agent_id,
                epoch: current_epoch
            });
        }

        Ok(())
    }
}

// ============================================================================
// Accounts
// ============================================================================

#[derive(Accounts)]
#[instruction(args: InitLeaseArgs)]
pub struct InitLease<'info> {
    /// Transaction fee payer — pays for lease PDA creation.
    /// When using Kora: this is Kora's pubkey.
    /// When direct: same as owner.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Agent wallet — authorises the USDC transfer from owner_usdc.
    /// Must be the wallet that owns the SATI NFT for this agent.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// Owner's USDC ATA (source of initial epoch payment).
    #[account(
        mut,
        associated_token::mint = usdc_mint,
        associated_token::authority = owner,
    )]
    pub owner_usdc: Account<'info, TokenAccount>,

    /// The agent's SATI NFT mint (Token-2022).
    pub agent_mint: InterfaceAccount<'info, MintInterface>,

    /// The owner's token account for the SATI NFT, proving they own the agent.
    #[account(
        token::mint = agent_mint,
        token::authority = owner,
        token::token_program = sati_token_program,
        constraint = owner_sati_token.amount == 1 @ LeaseError::NotOwner,
    )]
    pub owner_sati_token: InterfaceAccount<'info, TokenAccountInterface>,

    /// Lease state PDA. seeds = ["lease", agent_id]
    #[account(
        init,
        payer = payer,
        space = LeaseAccount::SIZE,
        seeds = [b"lease", args.agent_id.as_ref()],
        bump
    )]
    pub lease_account: Account<'info, LeaseAccount>,

    /// Protocol treasury USDC ATA — receives lease fees directly.
    /// Must be owned by TREASURY_PUBKEY.
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = treasury,
    )]
    pub treasury_usdc: Account<'info, TokenAccount>,

    /// CHECK: verified via associated_token constraint on treasury_usdc.
    #[account(address = TREASURY_PUBKEY)]
    pub treasury: UncheckedAccount<'info>,

    /// Token program for SATI NFTs (Token-2022).
    pub sati_token_program: Interface<'info, TokenInterface>,
    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(args: InitLeaseArgs)]
pub struct InitLease8004<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        associated_token::mint = usdc_mint,
        associated_token::authority = owner,
    )]
    pub owner_usdc: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = payer,
        space = LeaseAccount::SIZE,
        seeds = [b"lease", args.agent_id.as_ref()],
        bump
    )]
    pub lease_account: Account<'info, LeaseAccount>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = treasury,
    )]
    pub treasury_usdc: Account<'info, TokenAccount>,

    /// CHECK: verified via associated_token constraint on treasury_usdc.
    #[account(address = TREASURY_PUBKEY)]
    pub treasury: UncheckedAccount<'info>,

    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PayLease<'info> {
    /// Agent wallet — authorises the USDC transfer.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// Owner's USDC ATA (source).
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = owner,
    )]
    pub owner_usdc: Account<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [b"lease", lease_account.agent_id.as_ref()],
        bump = lease_account.bump,
        constraint = lease_account.owner == owner.key() @ LeaseError::NotOwner,
    )]
    pub lease_account: Account<'info, LeaseAccount>,

    /// Protocol treasury USDC ATA — receives lease fees directly.
    /// Must be owned by TREASURY_PUBKEY.
    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = treasury,
    )]
    pub treasury_usdc: Account<'info, TokenAccount>,

    /// CHECK: verified via associated_token constraint on treasury_usdc.
    #[account(address = TREASURY_PUBKEY)]
    pub treasury: UncheckedAccount<'info>,

    #[account(address = USDC_MINT)]
    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct TickLease<'info> {
    /// Permissionless — any signer can advance the lease state.
    pub caller: Signer<'info>,

    #[account(
        mut,
        seeds = [b"lease", lease_account.agent_id.as_ref()],
        bump = lease_account.bump,
    )]
    pub lease_account: Account<'info, LeaseAccount>,
}

// ============================================================================
// State
// ============================================================================

/// PDA: seeds = ["lease", agent_id]
#[account]
pub struct LeaseAccount {
    pub version: u8,
    pub agent_id: [u8; 32],
    pub owner: Pubkey,
    pub paid_through_epoch: u64,
    pub last_paid_slot: u64,
    pub current_epoch: u64,
    pub in_grace_period: bool,
    pub deactivated: bool,
    pub bump: u8,
}

impl LeaseAccount {
    /// 8 + 1 + 32 + 32 + 8 + 8 + 8 + 1 + 1 + 1 = 100 bytes
    pub const SIZE: usize = 8 + 1 + 32 + 32 + 8 + 8 + 8 + 1 + 1 + 1;
}

// ============================================================================
// Instruction arguments
// ============================================================================

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitLeaseArgs {
    pub agent_id: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct PayLeaseArgs {
    pub n_epochs: u64,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct LeaseInitialized {
    pub agent_id: [u8; 32],
    pub owner: Pubkey,
    pub slot: u64,
}

#[event]
pub struct LeasePaid {
    pub agent_id: [u8; 32],
    pub epoch: u64,
    pub slot: u64,
}

#[event]
pub struct GracePeriodEntered {
    pub agent_id: [u8; 32],
    pub epoch: u64,
}

#[event]
pub struct LeaseExpired {
    pub agent_id: [u8; 32],
    pub epoch: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum LeaseError {
    #[msg("Agent is deactivated and cannot pay lease")]
    AgentDeactivated,
    #[msg("n_epochs must be > 0")]
    ZeroEpochs,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Caller is not the agent owner")]
    NotOwner,
    #[msg("Agent mint argument does not match provided SATI mint account")]
    MintMismatch,
}
