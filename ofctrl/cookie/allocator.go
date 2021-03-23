package cookie

const (
	BitWidthRoundNum        = 16
	BitWidthFlowId          = 64 - BitWidthRoundNum
	RoundNumMask     uint64 = 0xffff_0000_0000_0000
	FlowIdMask       uint64 = 0x0000_ffff_ffff_ffff
)

type ID uint64

func newId(round uint64, flowId uint64) ID {
	r := uint64(0)
	r |= round << (64 - BitWidthRoundNum)
	r |= uint64(flowId)

	return ID(r)
}

func (i ID) RawId() uint64 {
	return uint64(i)
}

func (i ID) Round() uint64 {
	return i.RawId() >> (64 - BitWidthRoundNum)
}

type Allocator interface {
	RequestCookie(flowId uint64) ID
}

type allocator struct {
	roundNum uint64
}

func (a *allocator) RequestCookie(flowId uint64) ID {
	return newId(a.roundNum, flowId)
}

func NewAllocator(roundNum uint64) Allocator {
	a := &allocator{
		roundNum: roundNum,
	}
	return a
}

func RoundCookieWithMask(roundNum uint64) (uint64, uint64) {
	return roundNum << (64 - BitWidthRoundNum), RoundNumMask
}
