.PHONY: clean
clean:
	find . -not -path './.git/*' | git check-ignore --stdin | xargs -- rm -rf
