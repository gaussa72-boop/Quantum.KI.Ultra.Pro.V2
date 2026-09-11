# Quantum Payments & Credits

Shared prepaid-credit contract.

Credits are granted only after verified idempotent payment events. Stripe and crypto are provider adapters, not custody systems. Never commit payment secrets or crypto private keys. Production balances, payment intents, events, reservations and ledger entries must be persisted transactionally. Generation jobs should reserve credits before execution and release them on failure.
