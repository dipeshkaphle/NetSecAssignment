package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

func request() (bool, time.Duration) {
	time_now := time.Now()

	_, err := http.Get("https://delta.nitt.edu/~dipesh/output")
	if err != nil {
		fmt.Errorf("%v", err)
		return false, time.Since(time_now)
	}

	return true, time.Since(time_now)
}

func main() {
	var mt sync.Mutex
	n := os.Getenv("N")
	c := os.Getenv("C")

	loop_cnt := 1
	conc := 1

	if len(n) != 0 {
		tmp, e := strconv.Atoi(n)
		if e == nil {
			loop_cnt = tmp
		}
	}

	if len(c) != 0 {
		tmp, e := strconv.Atoi(c)
		if e == nil {
			conc = tmp
		}
	}
	fmt.Printf("Concurrency Level: %v, Num of Times: %v\n", conc, loop_cnt)

	sCnt := 0
	fCnt := 0
	successTimes := 0.0
	failureTimes := 0.0

	reportChan := make(chan int)
	var reporterWG sync.WaitGroup
	reporterWG.Add(1)

	go func() {
		defer reporterWG.Done()
		prevTime := time.Now()
		for {
			val := <-reportChan
			if val == 0 {
				fmt.Printf("Reporter thread signing off!!\n")
				break
			}
			if val%500 == 0 {
				curTime := time.Now()
				fmt.Printf("Completed %v requests in %v seconds!!\n", val, curTime.Sub(prevTime).Seconds())
				prevTime = curTime
			}
		}
	}()
	totalCnt := 0
	for i := 0; i < loop_cnt; i++ {
		var wg sync.WaitGroup

		for j := 0; j < conc; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, time_taken := request()
				if res {
					mt.Lock()
					totalCnt += 1
					sCnt = sCnt + 1
					successTimes = successTimes + time_taken.Seconds()
					reportChan <- totalCnt
					mt.Unlock()
				} else {
					mt.Lock()
					totalCnt += 1
					fCnt = fCnt + 1
					failureTimes = failureTimes + time_taken.Seconds()
					reportChan <- totalCnt
					mt.Unlock()
				}
			}()
		}
		wg.Wait()
	}
	reportChan <- 0
	reporterWG.Wait()
	fmt.Printf("Success: %d, Failure: %d\n", sCnt, fCnt)
	fmt.Printf("Avg Success Time: %v\n", successTimes/float64(sCnt))
	fmt.Printf("Avg Failure Time: %v\n", failureTimes/float64(fCnt))
}
