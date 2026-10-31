# Evaluation

| app | expected | got | ok |
|---|---|---|---|
| alias_import | reachable | reachable | yes |
| callback_ref | reachable | reachable | yes |
| class_method | reachable | reachable | yes |
| dead_import | not_affected | not_affected | yes |
| direct_call | reachable | reachable | yes |
| dynamic_getattr | uncertain | uncertain | yes |
| indirect_chain | reachable | reachable | yes |
| no_import | not_affected | not_affected | yes |
| relative_imports | reachable | reachable | yes |
| safe_only | not_affected | not_affected | yes |
| syntax_error | uncertain | uncertain | yes |
| transitive | reachable | reachable | yes |
| unknown_receiver | uncertain | uncertain | yes |

correct 13 / 13
false reachable: 0
missed reachable: 0
wrongly marked safe: 0
