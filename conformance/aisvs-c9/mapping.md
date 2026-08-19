# Vortex ↔ AISVS C9 Semantic Mapping

| External property | Vortex representation | Initial result |
|---|---|---|
| Four ordered reversibility classes | `ReversibilityClass` | PARTIALLY_ALIGNED |
| Externally reversible distinct from reversible | `ExternallyReversible` | ALIGNED |
| Unknown classification fails closed | `Unclassified` + `HardGate` | ALIGNED |
| Empty chain fails closed | `worst_case(empty) -> Unclassified` | ALIGNED |
| Class derived independently from agent assertion | Not yet implemented as registry binding | ARCHITECTURAL_GAP |
| Oversight monotonic in reversibility | `OversightRequirement` | ALIGNED |
| Irreversible + low consequence remains hard gated | Hard gate cannot be reduced | PARTIALLY_ALIGNED |
| High consequence + reversible elevates oversight | Consequence tier not yet implemented | ARCHITECTURAL_GAP |
| Worst property wins | `worst_case()` | ALIGNED |
| Chain gated by worst reachable reversibility | `ReversibilityClass::worst_case()` | PARTIALLY_ALIGNED |
| Bound / stale / unobserved declaration states | No equivalent binding model | INTENTIONAL_DIFFERENCE |
| Observation aging | No equivalent clock model | OUT_OF_SCOPE |
| Chain binding uses stalest link | No binding axis | INTENTIONAL_DIFFERENCE |
| Binding coverage gap | No equivalent coverage metric | OUT_OF_SCOPE |
