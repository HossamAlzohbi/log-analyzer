# Vakt

En lokal, offline sikkerhetsassistent: en åpen liten språkmodell finjustert (LoRA) på sikkerhetskilder, med kildehenvisninger og en rolig norsk personlighet.

**Status: fase 1 (datalag) er ferdig. Finjustering, RAG og evaluering kommer.**

## Datalaget

Kilder (åpne): MITRE ATT&CK, OWASP Cheat Sheet Series, SigmaHQ. Per i dag gir de 4480 eksempler (train 4041 / val 217 / test 222). Splitten gjøres per kilde-ID med hash, slik at samme kilde aldri havner i to sett.

```
pip install -r requirements.txt
python scripts/fetch_sources.py    # laster ned kildene til data/raw
python scripts/build_dataset.py    # bygger data/processed/*.jsonl
pytest
```

## Kjente begrensninger (ærlig)

- Rammen rundt hvert svar er norsk, men innholdet fra kildene er engelsk. Norsk kvalitet må måles og forbedres senere.
- Modellen er en finjustert åpen grunnmodell, ikke en modell trent fra bunnen.
