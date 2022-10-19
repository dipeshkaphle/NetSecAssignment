rm-docker:
	docker stop cgi-bin-vuln-app
	docker rm cgi-bin-vuln-app
run-docker: vuln
	docker compose up -d
stop-docker:
	docker compose down
vuln: 
	gcc -static -no-pie -o vuln vuln.c
clean:
	rm vuln

