System: Ride-Booking API
* Public endpoint: POST /api/request-ride
* Auth: API key in header, validated against DB
* Data flow: client -> API gateway -> booking service -> driver-matching service (3rd party)
* Stores: pickup/dropoff coordinates, rider_id, driver_id, trip history in Postgres
* Trust boundary: gateway is public internet-facing; booking service is internal-only
