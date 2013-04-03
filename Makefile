server:
	./node_modules/.bin/mocha \
                --reporter nyan test/servertest

test:
	./node_modules/.bin/mocha \
		--reporter nyan --ignore-leaks

.PHONY: test
