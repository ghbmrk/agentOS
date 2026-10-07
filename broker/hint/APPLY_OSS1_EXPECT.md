# PC1 Emit wire follow-up

Tip wires `holdAdapterGapPC1` into Emit.

Apply one-line change in `emitter_test.go` TestOSS1EveryHintLogged:

```
want := []Outcome{Queued, Duplicate, Withheld, Withheld, Refused} // adapter_gap changed_layout held (PC1)
```

(replacing `Asked` with `Withheld` for the adapter_gap record).

Validate: `cd broker && go test ./hint/ -count=1 -run 'OSS1EveryHintLogged|PC1'`
