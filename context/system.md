System: Payment API
  - Public endpoint: POST /api/charge
  - Auth: API key in header, validated against DB
  - Data flow: client -> API gateway -> charge service -> payment processor (3rd party)
  - Stores: card token (not raw PAN), customer_id, charge history in Postgres
  - Trust boundary: gateway is public internet-facing; charge service is internal-only
