# Go Crypto Benchmark 
## What's up?
Go Crypto Function's Benchmark

## Result
### For Ubuntu 19.04(64Bit)
* CPU: Intel® Core™ i7-5500U CPU @ 2.40GHz × 4 
* Memory : 8GB

Library|Suite |Sign/Verify|Average-time(per 10000 Sign/Verify)
|:---: |:---: |:---:      |:---
GO_ECDSA|P256|Sign  |0.3734 |
GO_ECDSA|P256|Verify|1.0293 |
GO_RSA  |2048|Sign  |20.0943|
GO_RSA  |2048|Verify|0.7843 |
GO_RSA  |3072|Sign  |53.5620|
GO_RSA  |3072|Verify|1.4540 |

