module example.com/vulnfix

go 1.22

require (
	example.com/dep v1.0.0
	example.com/fork v1.2.1
	example.com/quiet v1.0.0
)

replace example.com/fork => ./fork
