# Manual Facts

Concrete simulation-facing statements taken from the `Inside the Simulation` section of [simtower-manual.md](/Users/phulin/Documents/Projects/reaper/simtower-manual.md). These are manual claims, not reverse-engineered conclusions.

## Scope Notes From The Manual

- The section is explicitly described as explaining technical and behind-the-scenes calculations.
- The manual also says its numbers are for modeling purposes and may not be the precise internal formulas.
- The manual warns that customer totals in facility stress evaluations may not match the final shipped program exactly.

## Time And Frames

- One game time period consists of `300` time or animation frames.
- A frame is tied to the machine's clock speed and graphics draw speed rather than a fixed physical second.

## Elevator And Pathing Facts

- Transportation quality is presented as central to tenant satisfaction and tower success.
- Waiting for elevators increases tenant dissatisfaction.
- Transit design affects whether tenants reach destinations on time.
- Lateral distance to transit matters; tenants prefer nearby transit options.
- If tenants must search for alternate transit, the search adds stress.
- Long waits or poor transit placement can cause tenants to leave.

## Standard Elevators

- A newly placed standard elevator starts with one car.
- Additional cars are added by clicking a floor in an existing shaft.
- The floor where a car is added becomes that car's waiting floor.
- Waiting floors are shown in pink on the shaft.
- The tower is limited to `24` total elevator shafts across all elevator types.
- A standard elevator car holds up to `17` people.
- Standard elevators are for regular tenants only.
- Security staff do not use standard elevators.
- Housekeeping staff do not use standard elevators.
- Standard elevators can have up to `8` cars at the `5`-star rating.
- Standard elevators can be at most `30` floors tall, including basement levels.
- People shown on the right side of a shaft want to descend.
- People shown on the left side of a shaft want to ascend.

## Service Elevators

- Service elevators are for service and infrastructure personnel.
- Housekeeping staff use service elevators.
- Service elevator cars hold up to `17` people.
- Service elevators do not need to stop at lobbies.
- Service elevators do not need to stop at parking levels.
- Service elevators must stop at recycling centers.

## Express Elevators

- Express elevators are intended for trips of `15` floors or more.
- Express elevator transit zones are in `15`-floor increments, excluding underground levels.
- Express elevator waiting floors cannot be adjusted in the control panel.
- Express elevators are for regular tenants only, not service staff.
- Express elevators carry up to `36` passengers.
- Sky lobbies are intended to be placed every `15` floors for use with express elevators.
- Simtenants transfer between one elevator method and another only once in a trip.
- The manual describes sky lobbies as the most efficient long-distance transfer method.
- Express elevators only go to the `90`th floor in the Cathedral example.

## Stairs And Escalators

- Stairs and elevators are used simultaneously depending on floor traffic.
- Stairs can connect two floors.
- Tenants will not use more than `4` sets of stairs during one passage to a destination.
- Escalators reduce transit congestion.
- Escalator travel causes less stress than elevator travel because there is no wait to board.
- The manual says Simtenants will always choose escalators when they are available.
- Escalators can only be placed on commercial or public areas such as restaurants, fast food, shops, and lobbies.
- People will not take escalators more than `7` times during one passage to a destination.
- If two commercial areas are connected with escalators, they will share customers and revenue.
- On floors without sky lobbies, people will not transfer from elevators to stairs or escalators.
- Some tenants will switch from elevators to stairs.

## Waiting Floors And Scheduling

- Waiting floors should reflect building traffic patterns.
- A lobby waiting floor is useful because of heavy lobby traffic.
- If one floor is all offices and another is all restaurants, the manual recommends using the office floor as the waiting floor because its traffic is more bursty.
- The Elevator window exposes a `Waiting Car Response` setting measured in floors closer than moving cars.
- The Elevator window exposes a `Standard Floor Departure` setting measured in seconds to wait before departing.
- The Elevator window includes weekday and weekend scheduling controls.
- The Elevator window includes a simulation mode for previewing future elevator behavior.

## Rush Hour And Transfer Guidance

- The manual recommends setting standard elevators to express mode during rush hours.
- The manual specifically calls out hotel tenants leaving the building and office workers entering the building as rush-hour directional flows.
- Standard and express elevators are meant to be used together.
- Express elevators are described as faster over longer distances.
- People will use express elevators via sky lobbies for efficient transportation.

## Facility-Specific Pathing Claims

- Office workers arrive in the morning, leave in the evening, and go out for lunch at midday.
- Fast food businesses are used for snacks and lunch.
- Restaurants are used primarily at dinner hour.
- Hotel traffic patterns differ from office traffic patterns.
- Single hotel rooms hold one guest.
- Twin hotel rooms hold two guests.
- Hotel suites hold two guests.
- Occupied hotel suites require a parking place.
- Condos hold three inhabitants, excluding children.
- Condo purchase requires active traffic-network access according to the manual.
- Movie theater audiences enter from the upper level and exit from the lower level.
- After a movie, visitors frequent shops within five floors above or below the theater.
- Party Halls fill with `50` guests in the afternoon when the hotel-room condition is satisfied.
- Metro station visitors shop and eat only on underground levels.
- Metro station visitors can work and live in above-ground facilities.
- Parking areas must have some transport access, either stairs or elevators.
- Parking ramps must connect to the ground-floor lobby.

## Emergency And Service Pathing

- Security personnel use peripheral emergency stairs only.
- Security personnel do not use elevators.
- Security effectiveness depends on proximity to fires or bombs.
- Recycling centers require service-elevator access.
- VIP advancement can be blocked by poor transit service to hotel suites.

## Stress

- Stress is based on how many frames it takes a character to move from one destination to another.
- Stress has three visible levels up to a maximum of `300`.
- Stress below `80` is displayed as black.
- Stress from `80` to `119` is displayed as pink.
- Stress from `120` to `300` is displayed as red.

## Hotels And Offices

- Hotels and offices evaluate quality of life from the average stress of their inhabitants.
- The manual’s modeling formula is `Space Quality = 300 - (total stress / number of inhabitants)`.
- If space quality is greater than `200`, the evaluation is `A` and is displayed as a blue bar.
- If space quality is from `150` to `200`, the evaluation is `B` and is displayed as a yellow bar.
- If space quality is below `150`, the evaluation is `C` and is displayed as a red bar.
- Under `A`, inhabitants bring a friend to fill a vacant space at the next rest period.
- Under `B`, inhabitants stay.
- Under `C`, inhabitants leave at the end of the rest period.

## Restaurants And Fast Food

- Restaurants and fast food spaces are managed automatically.
- Their success is determined by transit design.
- Once placed, they stay unless destroyed.
- They use daily sales totals rather than tenant evaluations.
- Their customer total for the next day changes based on the stress of the day’s customers.
- When first placed, they start with `10` customers.
- The next day’s customer change is modeled in a range from `0` to `20`.
- `A` rating means a customer returns with a friend the next day.
- `B` rating means the customer returns alone.
- `C` rating means the customer boycotts the restaurant.
- Restaurant/fast-food daily ratings are modeled as:
- More than `25` customers gives `A`.
- `18` to `25` customers gives `B`.
- Fewer than `18` customers gives `C`.
- Restaurants have a maximum of `40` daily customers in the manual model.
- Fast food businesses have a maximum of `30` daily customers in the manual model.

## Shops

- Shops are rented on a quarterly basis.
- Shops are similar to restaurants, except tenants can leave if completely dissatisfied.
- Shop evaluations are based on daily customer count rather than renter stress.
- Shops start with `10` customers when placed.
- Shop daily ratings are modeled as:
- More than `20` customers gives `A`.
- `15` to `20` customers gives `B`.
- Fewer than `15` customers gives `C`.

## Condominiums

- Condos are sold for a one-time fee.
- Condos do not produce quarterly or daily income.
- Condo income is received when the space is connected to an active traffic network and then purchased.
- If condo inhabitants leave due to stress, the entire sale price is paid back.
- The manual describes condos as effectively functioning like a loan of the sale price until the inhabitants leave.
- Condo ratings are modeled as:
- `A`: inhabitants bring additional inhabitants to vacant condos.
- `B`: inhabitants continue living there.
- `C`: inhabitants leave and take their money with them.

## Movie Theater

- The player manages the movie theater directly.
- Daily sales depend on the popularity of the current movie.
- The audience enters from the top floor and exits from the bottom floor.
- Theater sales can be affected by congestion.
- After a movie ends, audience members tend to visit surrounding shops and restaurants within five floors above or below the theater.
- Theater personnel do not leave even when sales are bad.
