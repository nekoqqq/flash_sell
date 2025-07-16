package biz

import (
	"crypto/md5"
	"flash_sell"
	"flash_sell/conf"
	"fmt"
	"github.com/astaxie/beego/logs"
	"sync"
	"time"
)

var gFreqControlMap = &FreqControlMap{userControl: make(map[int]*FreqLimit)}

type Resp struct {
	Data      map[string]interface{} `json:"data"`
	ErrorCode int                    `json:"error_code"`
	ErrorMsg  string                 `json:"error_msg"`
}

type Req struct {
	ProductId int
	Source    string // 来源，安卓，苹果
	AuthCode  string
	FlashTime string // 抢购时间
	Nance     string
	// 1. 用户登录成功后，服务端设置两个cookie: userId和userAuth, md5(密钥+UserId)
	// 2. 抢购的时候需要用这两个cookie进行校验
	UserId       int
	UserAuthSign string
	AccessTime   time.Time // 访问时间
}

type FreqControlMap struct {
	userControl map[int]*FreqLimit // 每个用户当前时间的访问频次
	lock        sync.Mutex
}

type FreqLimit struct {
	count   int
	curTime time.Time
}

// DoCount 按秒统计
func (fl *FreqLimit) DoCount(curTime time.Time) int {
	if fl.curTime.Unix() != curTime.Unix() {
		fl.count = 0
		fl.curTime = curTime
	}
	fl.count += 1
	return fl.count
}

// GetCount 返回访问当前秒的访问次数
func (fl *FreqLimit) GetCount(curTime time.Time) int {
	if fl.curTime != curTime {
		return 0
	}
	return fl.count
}

func FlashSell(req *Req) (map[string]interface{}, int, error) {
	//data := map[int]interface{}{}
	//errCode := flash_sell.Succeed

	// 1. 用户信息检查
	err := func() error {
		authData := fmt.Sprintf("%d:%s", req.UserId, conf.GFlashSellConf.CookieSecretKey)
		authSign := fmt.Sprintf("%x", md5.Sum([]byte(authData)))
		logs.Debug("req: %v, authData: %v, authSign: %v", req, authData, authSign)
		if authSign != req.UserAuthSign {
			return fmt.Errorf("invalid user auth: %v", authSign)
		}
		return nil
	}()
	if err != nil {
		errCode := flash_sell.InvalidUser
		logs.Warn("用户id: %v非法, req: %v, errCode: %v, err: %v", req.UserId, req, errCode, err)
		return nil, flash_sell.InvalidUser, nil
	}

	// 2. 用户反作弊
	err = func() error {
		gFreqControlMap.lock.Lock()
		defer gFreqControlMap.lock.Unlock()
		freqLimit, ok := gFreqControlMap.userControl[req.UserId]
		if !ok {
			freqLimit = &FreqLimit{}
			gFreqControlMap.userControl[req.UserId] = freqLimit
		}
		accessCount := freqLimit.DoCount(req.AccessTime)
		fmt.Printf("Access Count: %d\n", accessCount)
		if accessCount > conf.GFlashSellConf.UserAccessLimit {
			return fmt.Errorf("user access limit exceeded")
		}
		return nil
	}()
	if err != nil {
		errCode := flash_sell.UserFreqControl
		logs.Warn("用户id: %v超过频率控制, req: %v, errCode: %v", req.UserId, req, errCode)
		return nil, flash_sell.UserFreqControl, err
	}

	return nil, flash_sell.Succeed, nil
}

// FlashSellInfo 返回的配置信息，出错码，出错原因
func FlashSellInfo(productId int) (map[int]interface{}, int, error) {
	data := map[int]interface{}{}
	errCode := flash_sell.Succeed
	var common = func(productId int, value conf.ETCDProductInfo) {
		isStart, isEnd, status := false, false, "活动尚未开始"
		productStatus := value.Status

		if productStatus != flash_sell.ProductNormal {
			status = productStatus.String()
		} else {
			now := time.Now()
			if now.Sub(value.StartTime) > 0 {
				isStart = true
				status = "活动开始"
			}

			if now.Sub(value.EndTime) > 0 {
				isStart, isEnd = false, true
				status = "活动已经结束"
			}
		}
		data[productId] = map[string]interface{}{
			"start":  isStart, // 可能和客户端的时间不一致，所以没法直接用这个时间
			"end":    isEnd,
			"status": status, // 是否可以买，如果不可以买，前端就置成灰色了
		}
	}
	// TODO 这里有race竞争需要检测出来
	if value, ok := conf.GFlashSellConf.EtcdProductInfos[productId]; !ok {
		logs.Error("product_id: %v不存在配置中心中", productId)
		for productId, value := range conf.GFlashSellConf.EtcdProductInfos {
			common(productId, value)
		}
		errCode = flash_sell.InvalidParms
	} else {
		logs.Debug("获取配置成功, product: %v, 配置: %v", productId, value)
		common(productId, value)
	}
	return data, errCode, nil
}
