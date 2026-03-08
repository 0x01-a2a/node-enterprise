use anchor_lang::prelude::*;
use anchor_lang::solana_program::program_pack::Pack;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, CloseAccount, Mint, Token, TokenAccount, Transfer},
};

declare_id!("Es69yGQ7XnwhHjoj3TRv5oigUsQzCvbRYGXJTFcJrT9F");

/// Protocol treasury — receives settlement fees.
pub const TREASURY_PUBKEY: Pubkey = pubkey!("qw4hzfV7UUXTrNh3hiS9Q8KSPMXWUusNoyFKLvtcMMX");
/// Canonical USDC mint enforced by escrow flows.
#[cfg(feature = "devnet")]
pub const USDC_MINT: Pubkey = pubkey!("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
#[cfg(not(feature = "devnet"))]
pub const USDC_MINT: Pubkey = pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");

/// Settlement fee in basis points (50 bps = 0.5%).
/// Deducted from task amount at release; remainder goes to provider.
/// Cancellations are free (no delivery occurred).
pub const FEE_BPS: u64 = 50;

/// Default timeout: ~7 days at 400 ms/slot.
pub const DEFAULT_TIMEOUT_SLOTS: u64 = 1_512_000;

// ============================================================================
// Escrow Program
//
// Generic USDC escrow for agent-to-agent payments.
// Any SATI-registered agent can use this program directly — no 0x01 mesh
// node required.
//
// Economic flow:
//   Requester locks:  amount  (task payment)  +  notary_fee  (notary compensation)
//
//   On approve_payment:
//     → provider receives  amount - protocol_fee
//     → treasury receives  protocol_fee          (FEE_BPS of amount)
//     → notary  receives   notary_fee            (if notary was designated)
//
//   On claim_timeout (notary absent / didn't act):
//     → provider receives  amount + notary_fee - protocol_fee
//                          (provider absorbs notary share as penalty for notary inaction)
//     → treasury receives  protocol_fee
//
//   On cancel_escrow:
//     → requester reclaims amount + notary_fee   (full refund, no fee)
//
// Instructions:
//   lock_payment(conversation_id, amount, notary_fee, notary, timeout_slots)
//   approve_payment()   — by requester or notary
//   claim_timeout()     — by provider after timeout
//   cancel_escrow()     — by requester before settlement
// ============================================================================

#[program]
pub mod escrow {
    use super::*;

    /// Lock USDC into escrow for a payment to `provider`.
    ///
    /// `conversation_id` — 16-byte reference linking this escrow to the
    ///   off-chain negotiation (maps to the 0x01 protocol conversation_id,
    ///   but can be any shared identifier).
    ///
    /// `amount` — USDC task payment (6 decimal places). Must be > 0.
    ///
    /// `notary_fee` — USDC amount reserved for the notary (6 decimal places).
    ///   Must be 0 when `notary` is None; may be 0 even when notary is Some
    ///   (free notarization). Total locked = amount + notary_fee.
    ///
    /// `notary` — optional trusted third party authorised to approve payment.
    ///   If None, only the requester can approve.
    ///
    /// `timeout_slots` — slots after which provider may claim without approval.
    ///   Pass 0 to use DEFAULT_TIMEOUT_SLOTS.
    pub fn lock_payment(
        ctx: Context<LockPayment>,
        conversation_id: [u8; 16],
        amount: u64,
        notary_fee: u64,
        notary: Option<Pubkey>,
        timeout_slots: u64,
    ) -> Result<()> {
        #[cfg(not(feature = "localtest"))]
        require!(
            ctx.accounts.usdc_mint.key() == USDC_MINT,
            EscrowError::InvalidMint
        );

        require!(amount > 0, EscrowError::ZeroAmount);
        require!(
            notary.is_some() || notary_fee == 0,
            EscrowError::NotaryFeeWithoutNotary,
        );

        let clock = Clock::get()?;
        let timeout = if timeout_slots == 0 {
            DEFAULT_TIMEOUT_SLOTS
        } else {
            timeout_slots
        };
        let total = amount
            .checked_add(notary_fee)
            .ok_or(EscrowError::AmountOverflow)?;

        let escrow = &mut ctx.accounts.escrow_account;
        escrow.version = 1;
        escrow.requester = ctx.accounts.requester.key();
        escrow.provider = ctx.accounts.provider.key();
        escrow.notary = notary;
        escrow.amount = amount;
        escrow.notary_fee = notary_fee;
        escrow.created_slot = clock.slot;
        escrow.timeout_slots = timeout;
        escrow.conversation_id = conversation_id;
        escrow.released = false;
        escrow.bump = ctx.bumps.escrow_account;

        // Transfer amount + notary_fee from requester into vault.
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.requester_usdc.to_account_info(),
                to: ctx.accounts.escrow_vault.to_account_info(),
                authority: ctx.accounts.requester.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, total)?;

        msg!(
            "Escrow locked: {} USDC task + {} notary_fee | timeout {} slots",
            amount,
            notary_fee,
            timeout,
        );
        Ok(())
    }

    /// Approve and release payment to the provider (and fee to notary).
    ///
    /// May be called by the requester or, if a notary was designated, by the notary.
    ///
    /// Settlement:
    ///   provider  ← amount  − protocol_fee
    ///   treasury  ← protocol_fee  (FEE_BPS of amount)
    ///   notary    ← notary_fee    (if notary was designated and fee > 0)
    pub fn approve_payment(ctx: Context<ApprovePayment>) -> Result<()> {
        let escrow = &ctx.accounts.escrow_account;

        require!(!escrow.released, EscrowError::AlreadySettled);

        // Caller must be requester or designated notary.
        let caller = ctx.accounts.approver.key();
        let authorized =
            caller == escrow.requester || escrow.notary.map(|n| n == caller).unwrap_or(false);
        require!(authorized, EscrowError::Unauthorized);

        let amount = escrow.amount;
        let notary_fee = escrow.notary_fee;
        let fee = amount.saturating_mul(FEE_BPS) / 10_000;
        let payout = amount.saturating_sub(fee);
        let has_notary_payout = escrow.notary.is_some() && notary_fee > 0;
        let designated_notary = escrow.notary;

        let bump = escrow.bump;
        let requester = escrow.requester;
        let provider = escrow.provider;
        let conv_id = escrow.conversation_id;

        ctx.accounts.escrow_account.released = true;

        let seeds: &[&[&[u8]]] = &[&[
            b"escrow",
            requester.as_ref(),
            provider.as_ref(),
            &conv_id,
            &[bump],
        ]];

        let vault_auth_seeds: &[&[&[u8]]] = &[&[
            b"escrow_vault",
            ctx.accounts.escrow_account.to_account_info().key.as_ref(),
            &[ctx.bumps.escrow_vault_authority],
        ]];

        // Pay provider (amount - protocol_fee).
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.escrow_vault.to_account_info(),
                    to: ctx.accounts.provider_usdc.to_account_info(),
                    authority: ctx.accounts.escrow_vault_authority.to_account_info(),
                },
                vault_auth_seeds,
            ),
            payout,
        )?;

        // Pay protocol fee to treasury.
        if fee > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.escrow_vault.to_account_info(),
                        to: ctx.accounts.treasury_usdc.to_account_info(),
                        authority: ctx.accounts.escrow_vault_authority.to_account_info(),
                    },
                    vault_auth_seeds,
                ),
                fee,
            )?;
        }

        // Pay notary fee (if notary was designated and fee > 0).
        if has_notary_payout {
            // Validate that notary_usdc is the designated notary's USDC token account.
            let expected_notary = designated_notary.ok_or(EscrowError::Unauthorized)?;
            {
                let notary_data = ctx.accounts.notary_usdc.try_borrow_data()?;
                let parsed = anchor_spl::token::spl_token::state::Account::unpack(&notary_data)
                    .map_err(|_| EscrowError::InvalidNotaryUsdc)?;
                require!(
                    parsed.owner == expected_notary,
                    EscrowError::InvalidNotaryUsdc
                );
                require!(
                    parsed.mint == ctx.accounts.usdc_mint.key(),
                    EscrowError::InvalidNotaryUsdc
                );
            } // borrow dropped here before the CPI

            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.escrow_vault.to_account_info(),
                        to: ctx.accounts.notary_usdc.to_account_info(),
                        authority: ctx.accounts.escrow_vault_authority.to_account_info(),
                    },
                    vault_auth_seeds,
                ),
                notary_fee,
            )?;
        }

        // Close vault ATA — return rent (~0.002 SOL) to requester.
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.escrow_vault.to_account_info(),
                destination: ctx.accounts.requester.to_account_info(),
                authority: ctx.accounts.escrow_vault_authority.to_account_info(),
            },
            vault_auth_seeds,
        ))?;

        let _ = seeds; // suppress unused warning
        msg!(
            "Approved: {} USDC to provider, {} fee, {} notary",
            payout,
            fee,
            notary_fee,
        );
        Ok(())
    }

    /// Provider claims full vault after timeout without requester or notary approval.
    ///
    /// Provider absorbs the notary_fee (notary failed to act within timeout).
    ///   provider  ← amount + notary_fee − protocol_fee
    ///   treasury  ← protocol_fee  (FEE_BPS of amount only)
    pub fn claim_timeout(ctx: Context<ClaimTimeout>) -> Result<()> {
        let escrow = &ctx.accounts.escrow_account;

        require!(!escrow.released, EscrowError::AlreadySettled);
        require!(
            ctx.accounts.provider.key() == escrow.provider,
            EscrowError::Unauthorized,
        );

        let clock = Clock::get()?;
        require!(
            clock.slot >= escrow.created_slot.saturating_add(escrow.timeout_slots),
            EscrowError::TimeoutNotReached,
        );

        let amount = escrow.amount;
        let notary_fee = escrow.notary_fee;
        let fee = amount.saturating_mul(FEE_BPS) / 10_000;
        // Provider absorbs notary_fee since notary did not act.
        let payout = amount.saturating_add(notary_fee).saturating_sub(fee);
        let requester = escrow.requester;
        let provider = escrow.provider;
        let conv_id = escrow.conversation_id;
        let bump = escrow.bump;

        ctx.accounts.escrow_account.released = true;

        let vault_auth_seeds: &[&[&[u8]]] = &[&[
            b"escrow_vault",
            ctx.accounts.escrow_account.to_account_info().key.as_ref(),
            &[ctx.bumps.escrow_vault_authority],
        ]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.escrow_vault.to_account_info(),
                    to: ctx.accounts.provider_usdc.to_account_info(),
                    authority: ctx.accounts.escrow_vault_authority.to_account_info(),
                },
                vault_auth_seeds,
            ),
            payout,
        )?;

        if fee > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.escrow_vault.to_account_info(),
                        to: ctx.accounts.treasury_usdc.to_account_info(),
                        authority: ctx.accounts.escrow_vault_authority.to_account_info(),
                    },
                    vault_auth_seeds,
                ),
                fee,
            )?;
        }

        // Close vault ATA — return rent (~0.002 SOL) to requester.
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.escrow_vault.to_account_info(),
                destination: ctx.accounts.requester.to_account_info(),
                authority: ctx.accounts.escrow_vault_authority.to_account_info(),
            },
            vault_auth_seeds,
        ))?;

        let _ = (requester, provider, conv_id, bump);
        msg!(
            "Timeout claimed: {} USDC to provider (incl. {} notary_fee), {} fee",
            payout,
            notary_fee,
            fee,
        );
        Ok(())
    }

    /// Requester cancels the escrow and reclaims their full USDC (amount + notary_fee).
    ///
    /// Only callable by the requester, only while not yet settled. No protocol fee.
    pub fn cancel_escrow(ctx: Context<CancelEscrow>) -> Result<()> {
        let escrow = &ctx.accounts.escrow_account;

        require!(!escrow.released, EscrowError::AlreadySettled);
        require!(
            ctx.accounts.requester.key() == escrow.requester,
            EscrowError::Unauthorized,
        );
        let clock = Clock::get()?;
        require!(
            clock.slot < escrow.created_slot.saturating_add(escrow.timeout_slots),
            EscrowError::TimeoutAlreadyReached,
        );

        let amount = escrow.amount;
        let notary_fee = escrow.notary_fee;
        let total = amount.saturating_add(notary_fee);
        let requester = escrow.requester;
        let provider = escrow.provider;
        let conv_id = escrow.conversation_id;
        let bump = escrow.bump;

        ctx.accounts.escrow_account.released = true;

        let vault_auth_seeds: &[&[&[u8]]] = &[&[
            b"escrow_vault",
            ctx.accounts.escrow_account.to_account_info().key.as_ref(),
            &[ctx.bumps.escrow_vault_authority],
        ]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.escrow_vault.to_account_info(),
                    to: ctx.accounts.requester_usdc.to_account_info(),
                    authority: ctx.accounts.escrow_vault_authority.to_account_info(),
                },
                vault_auth_seeds,
            ),
            total,
        )?;

        // Close vault ATA — return rent (~0.002 SOL) to requester.
        token::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            CloseAccount {
                account: ctx.accounts.escrow_vault.to_account_info(),
                destination: ctx.accounts.requester.to_account_info(),
                authority: ctx.accounts.escrow_vault_authority.to_account_info(),
            },
            vault_auth_seeds,
        ))?;

        let _ = (requester, provider, conv_id, bump);
        msg!("Escrow cancelled: {} USDC returned to requester", total);
        Ok(())
    }
}

// ============================================================================
// Accounts
// ============================================================================

#[derive(Accounts)]
#[instruction(conversation_id: [u8; 16])]
pub struct LockPayment<'info> {
    #[account(mut)]
    pub requester: Signer<'info>,

    /// CHECK: pubkey only — provider does not sign at lock time
    pub provider: UncheckedAccount<'info>,

    #[account(
        init,
        payer  = requester,
        space  = EscrowAccount::SIZE,
        seeds  = [b"escrow", requester.key().as_ref(), provider.key().as_ref(), &conversation_id],
        bump,
    )]
    pub escrow_account: Account<'info, EscrowAccount>,

    #[account(
        seeds = [b"escrow_vault", escrow_account.key().as_ref()],
        bump,
    )]
    /// CHECK: PDA authority for the vault ATA
    pub escrow_vault_authority: UncheckedAccount<'info>,

    #[account(
        init_if_needed,
        payer                        = requester,
        associated_token::mint       = usdc_mint,
        associated_token::authority  = escrow_vault_authority,
    )]
    pub escrow_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = requester,
    )]
    pub requester_usdc: Account<'info, TokenAccount>,

    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ApprovePayment<'info> {
    /// Requester or notary — validated in instruction logic.
    pub approver: Signer<'info>,

    #[account(
        mut,
        close = requester,
        seeds = [
            b"escrow",
            escrow_account.requester.as_ref(),
            escrow_account.provider.as_ref(),
            &escrow_account.conversation_id,
        ],
        bump  = escrow_account.bump,
    )]
    pub escrow_account: Account<'info, EscrowAccount>,

    /// CHECK: Payer/Requester who will receive the rent lamports upon account closing.
    #[account(mut, address = escrow_account.requester)]
    pub requester: UncheckedAccount<'info>,

    #[account(
        seeds = [b"escrow_vault", escrow_account.key().as_ref()],
        bump,
    )]
    /// CHECK: PDA authority for the vault ATA
    pub escrow_vault_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = escrow_vault_authority,
    )]
    pub escrow_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = escrow_account.provider,
    )]
    pub provider_usdc: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = treasury,
    )]
    pub treasury_usdc: Account<'info, TokenAccount>,

    /// CHECK: address constraint enforces treasury pubkey
    #[account(address = TREASURY_PUBKEY)]
    pub treasury: UncheckedAccount<'info>,

    /// CHECK: ATA of the notary for USDC.
    /// Must be a valid initialized USDC token account when escrow.notary is Some
    /// and escrow.notary_fee > 0. Any pubkey is acceptable otherwise (transfer skipped).
    #[account(mut)]
    pub notary_usdc: UncheckedAccount<'info>,

    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClaimTimeout<'info> {
    pub provider: Signer<'info>,

    #[account(
        mut,
        close = requester,
        seeds = [
            b"escrow",
            escrow_account.requester.as_ref(),
            escrow_account.provider.as_ref(),
            &escrow_account.conversation_id,
        ],
        bump  = escrow_account.bump,
    )]
    pub escrow_account: Account<'info, EscrowAccount>,

    /// CHECK: Payer/Requester who will receive the rent lamports upon account closing.
    #[account(mut, address = escrow_account.requester)]
    pub requester: UncheckedAccount<'info>,

    #[account(
        seeds = [b"escrow_vault", escrow_account.key().as_ref()],
        bump,
    )]
    /// CHECK: PDA authority for the vault ATA
    pub escrow_vault_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = escrow_vault_authority,
    )]
    pub escrow_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = provider,
    )]
    pub provider_usdc: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = treasury,
    )]
    pub treasury_usdc: Account<'info, TokenAccount>,

    /// CHECK: address constraint enforces treasury pubkey
    #[account(address = TREASURY_PUBKEY)]
    pub treasury: UncheckedAccount<'info>,

    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CancelEscrow<'info> {
    #[account(mut)]
    pub requester: Signer<'info>,

    #[account(
        mut,
        close = requester,
        seeds = [
            b"escrow",
            escrow_account.requester.as_ref(),
            escrow_account.provider.as_ref(),
            &escrow_account.conversation_id,
        ],
        bump  = escrow_account.bump,
    )]
    pub escrow_account: Account<'info, EscrowAccount>,

    #[account(
        seeds = [b"escrow_vault", escrow_account.key().as_ref()],
        bump,
    )]
    /// CHECK: PDA authority for the vault ATA
    pub escrow_vault_authority: UncheckedAccount<'info>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = escrow_vault_authority,
    )]
    pub escrow_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        associated_token::mint      = usdc_mint,
        associated_token::authority = requester,
    )]
    pub requester_usdc: Account<'info, TokenAccount>,

    pub usdc_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}

// ============================================================================
// State
// ============================================================================

#[account]
pub struct EscrowAccount {
    /// Struct version for migration safety.
    pub version: u8, // 1
    /// The party who locked payment and can approve release.
    pub requester: Pubkey, // 32
    /// The party who will receive payment on approval or timeout.
    pub provider: Pubkey, // 32
    /// Optional trusted third party (notary) authorised to approve payment.
    pub notary: Option<Pubkey>, // 1 + 32 = 33
    /// USDC task amount locked (6 decimal places).
    pub amount: u64, // 8
    /// USDC notary compensation locked (6 decimal places). 0 if no notary fee.
    pub notary_fee: u64, // 8
    /// Slot when escrow was created.
    pub created_slot: u64, // 8
    /// Slots after creation_slot before provider may claim without approval.
    pub timeout_slots: u64, // 8
    /// Shared reference ID (maps to protocol conversation_id).
    pub conversation_id: [u8; 16], // 16
    /// True once settled (approved, claimed, or cancelled).
    pub released: bool, // 1
    /// PDA bump.
    pub bump: u8, // 1
}

impl EscrowAccount {
    /// 8 disc + 1 + 32 + 32 + 33 + 8 + 8 + 8 + 8 + 16 + 1 + 1
    pub const SIZE: usize = 8 + 1 + 32 + 32 + 33 + 8 + 8 + 8 + 8 + 16 + 1 + 1;
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum EscrowError {
    #[msg("Escrow has already been settled")]
    AlreadySettled,
    #[msg("Caller is not authorised to perform this action")]
    Unauthorized,
    #[msg("Timeout has not been reached yet")]
    TimeoutNotReached,
    #[msg("Escrow amount must be greater than zero")]
    ZeroAmount,
    #[msg("notary_fee must be zero when no notary is designated")]
    NotaryFeeWithoutNotary,
    #[msg("Amount overflow: amount + notary_fee exceeds u64")]
    AmountOverflow,
    #[msg("Cannot cancel escrow after timeout is reached")]
    TimeoutAlreadyReached,
    #[msg("notary_usdc must be the designated notary's USDC token account")]
    InvalidNotaryUsdc,
    #[msg("usdc_mint must be the canonical USDC mint")]
    InvalidMint,
}
