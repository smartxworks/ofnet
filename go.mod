module github.com/contiv/ofnet

go 1.15

require (
	github.com/Sirupsen/logrus v0.8.8-0.20160119000032-f7f79f729e0f
	github.com/contiv/libOpenflow v0.0.0-20200107061746-e3817550c83b
	github.com/contiv/libovsdb v0.0.0-20160406174930-bbc744d8ddc8
	github.com/deckarep/golang-set v1.7.1
	github.com/google/gopacket v1.1.18
	github.com/jainvipin/bitset v1.0.1-0.20150123060543-1f0c6de81a62
	github.com/osrg/gobgp v0.0.0
	github.com/spf13/pflag v1.0.5
	github.com/streamrail/concurrent-map v0.0.0-20160823150647-8bf1e9bacbf6
	github.com/vishvananda/netlink v0.0.0-20170220200719-fe3b5664d23a
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	google.golang.org/grpc v1.35.0
)

replace github.com/osrg/gobgp => github.com/zwtop/gobgp v0.0.0-20210127101833-12edfc1f4514
