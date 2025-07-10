package biz

import (
	"flash_sell"
	"flash_sell/conf"
	"github.com/astaxie/beego/logs"
	"time"
)

// FlashSellInfo 返回的配置信息，出错码，出错原因
func FlashSellInfo(productId int) (map[string]interface{}, int, error) {
	data := map[string]interface{}{
		"product_id":      productId,
		"flash sell info": "hello world",
	}
	// TODO 这里有race竞争需要检测出来
	if value, ok := conf.GFlashSellConf.EtcdProductInfos[productId]; !ok {
		logs.Error("product_id: %v不存在配置中心中", productId)
	} else {
		logs.Debug("获取配置成功, product: %v, 配置: %v", productId, value)
		isStart, isEnd := false, false

		if (time.Now().Sub(value.StartTime)) > 0 {
			isStart = true
		}
		if (time.Now().Sub(value.EndTime)) > 0 {
			isStart, isEnd = false, true
		}

		data["start"] = isStart // 可能和客户端的时间不一致，所以没法直接用这个时间
		data["end"] = isEnd
		data["status"] = value.Status.String() // 是否可以买，如果不可以买，前端就置成灰色了
	}

	return data, flash_sell.Succeed, nil
}
