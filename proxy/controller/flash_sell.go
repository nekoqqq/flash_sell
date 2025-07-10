package controller

import (
	"flash_sell"
	"flash_sell/biz"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"runtime"
)

type Resp struct {
	Data      map[string]interface{} `json:"data"`
	ErrorCode int                    `json:"error_code"`
	ErrorMsg  string                 `json:"error_msg"`
}

type FlashSellController struct {
	beego.Controller // 继承
}

func (c *FlashSellController) FlashSell() {
	defer c.ServeJSON()
	c.Data["json"] = map[string]interface{}{
		"success":    true,
		"goroutines": runtime.NumGoroutine(),
	}
}
func (c *FlashSellController) FlashSellInfos() {

}

func (c *FlashSellController) FlashSellInfo() {
	resp := Resp{
		Data:      make(map[string]interface{}),
		ErrorCode: flash_sell.Succeed,
	}
	defer func() {
		c.Data["json"] = resp
		c.ServeJSON()
	}()

	// 1. 参数校验优先级最高，从请求参数中获取product_id
	productId, err := c.GetInt("product_id")
	if err != nil {
		resp.ErrorCode = flash_sell.InvalidParms
		resp.ErrorMsg = "非法商品ID"
		logs.Warn("请求参数错误，获取解析商品id失败, error: %v", err)
		return
	}

	// 2. 业务逻辑执行
	bizData, bizErrCode, err := biz.FlashSellInfo(productId)
	if err != nil || bizErrCode != flash_sell.Succeed {
		resp.Data["biz_data"] = bizData
		resp.ErrorCode = bizErrCode
		resp.ErrorMsg = "服务内部处理错误"
		logs.Error("Flash Sell Info调用失败, product_id: %v, biz error code: %v, error: %v", productId, bizErrCode, err)
		return
	}

	// 3. 成功数据处理
	resp.Data["biz_data"] = bizData

	// 4. 调试日志（可选）
	logs.Debug("请求成功, product_id: %v", productId)
}
