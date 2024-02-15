.PHONY: pdf

PDF_PREVIEWER = zathura
GENERATE_CMD = latexmk -xelatex -bibtex -e '$$pdf_previewer=${PDF_PREVIEWER}'
FILE_NAME = main.tex

pdf:
	$(GENERATE_CMD) $(FILE_NAME)

.PHONY: watch
watch:
	$(GENERATE_CMD) -pvc $(FILE_NAME)

.PHONY: clean
clean:
	latexmk -C
