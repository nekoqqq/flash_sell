package biz

import (
	"flash_sell"
	"flash_sell/conf"
	"github.com/astaxie/beego/logs"
	"time"
)

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
