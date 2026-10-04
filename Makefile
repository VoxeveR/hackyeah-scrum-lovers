.PHONY: test demo demo-attack demo-loop demo-live serve load audit verify feed-sign feed-verify feed-serve scan-model report

test:            ## testy bez modeli i kluczy (to uruchamiają sędziowie)
	uv run pytest -q

demo:            ## scenariusz KYC bez ataku, skryptowany model
	uv run spiregate demo --scenario benign

demo-attack:     ## ten sam scenariusz, strona zawiera ukrytą instrukcję
	uv run spiregate demo --scenario attack

demo-loop:       ## agent ponawia w kółko to samo wywołanie, bezpiecznik pętli go zatrzymuje
	uv run spiregate demo --scenario loop

demo-live:       ## prawdziwe OpenAI (wymaga OPENAI_API_KEY w .env)
	uv run spiregate demo --scenario attack --model gpt-5-mini

serve:           ## gateway jako serwer: base_url = http://127.0.0.1:8787/v1
	uv run spiregate serve

load:            ## 100 żądań symulowanej floty do działającego gatewaya (podgląd: /ui/#/engine)
	uv run spiregate load --n 100

audit:
	uv run spiregate audit show

verify:
	uv run spiregate audit verify

feed-sign:       ## po edycji feed/signatures.yaml: walidacja, przykłady sygnatur, nowa wersja, podpis
	uv run spiregate feed sign

feed-verify:     ## sprawdza podpis paczki kluczami zaufanymi w polityce
	uv run spiregate feed verify

feed-serve:      ## demonstracyjny serwer threat-intel; w polityce: feed.source: http://127.0.0.1:8788/v1/feed/bundle
	uv run spiregate feed serve

scan-model:      ## skan modeli bez ładowania: czysty i złośliwy .pt (pickle z os.system)
	uv run spiregate feed demo-models
	-uv run spiregate scan-model demo/models/clean_model.pt demo/models/evil_model.pt

report:          ## daily AI security report from the decision log (OpenAI with a key, template without one)
	uv run spiregate report --assess
