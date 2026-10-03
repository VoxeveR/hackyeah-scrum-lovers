.PHONY: test demo demo-attack demo-live serve audit verify

test:            ## testy bez modeli i kluczy (to uruchamiają sędziowie)
	uv run pytest -q

demo:            ## scenariusz KYC bez ataku, skryptowany model
	uv run spiregate demo --scenario benign

demo-attack:     ## ten sam scenariusz, strona zawiera ukrytą instrukcję
	uv run spiregate demo --scenario attack

demo-live:       ## prawdziwe OpenAI (wymaga OPENAI_API_KEY w .env)
	uv run spiregate demo --scenario attack --model gpt-5-mini

serve:           ## gateway jako serwer: base_url = http://127.0.0.1:8787/v1
	uv run spiregate serve

audit:
	uv run spiregate audit show

verify:
	uv run spiregate audit verify
