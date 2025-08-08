.PHONY: get-presentation clean-presentation

# Target to fetch DEFCON 33 presentation materials
get-presentation:
	@echo "Fetching DEFCON 33 Model Security presentation materials..."
	@mkdir -p presentation
	wget -P presentation/ "https://media.defcon.org/DEF%20CON%2033/DEF%20CON%2033%20presentations/Cyrus%20Parzian%20-%20Loading%20Models%2C%20Launching%20Shells%20Abusing%20AI%20File%20Formats%20for%20Code%20Execution.pdf"
	wget -P presentation/ "https://media.defcon.org/DEF%20CON%2033/DEF%20CON%2033%20presentations/Cyrus%20Parzian%20-%20Loading%20Models%2C%20Launching%20Shells%20Abusing%20AI%20File%20Formats%20for%20Code%20Execution%20Demo1%20v2.mp4"
	wget -P presentation/ "https://media.defcon.org/DEF%20CON%2033/DEF%20CON%2033%20presentations/Cyrus%20Parzian%20-%20Loading%20Models%2C%20Launching%20Shells%20Abusing%20AI%20File%20Formats%20for%20Code%20Execution%20Demo2%20v2.mp4"
	wget -P presentation/ "https://media.defcon.org/DEF%20CON%2033/DEF%20CON%2033%20presentations/Cyrus%20Parzian%20-%20Loading%20Models%2C%20Launching%20Shells%20Abusing%20AI%20File%20Formats%20for%20Code%20Execution%20Demo3%20v2.mp4"
	wget -P presentation/ "https://media.defcon.org/DEF%20CON%2033/DEF%20CON%2033%20presentations/Cyrus%20Parzian%20-%20Loading%20Models%2C%20Launching%20Shells%20Abusing%20AI%20File%20Formats%20for%20Code%20Execution%20Demo4%20v2.mp4"

clean-presentation:
	@echo "Cleaning presentation materials..."
	@rm -rf presentation/

# Setup Python environment with system PyTorch
setup-env:
	@echo "Setting up Python environment with system py311-pytorch..."
	python3.11 -m venv --system-site-packages venv
	./venv/bin/pip install numpy transformers datasets tiktoken wandb tqdm