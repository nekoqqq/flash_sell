package controller

import (
	"flash_sell"
	"flash_sell/biz"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
	"strconv"
	"time"
)

type FlashSellController struct {
	beego.Controller // 继承
}

func (c *FlashSellController) FlashSell() {
	resp := biz.Resp{
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

	source := c.GetString("source")
	autCode := c.GetString("autCode")
	flashTime := c.GetString("flash_time")
	nance := c.GetString("nance")
	userAuthSign := c.Ctx.GetCookie("user_auth_sign")
	userId, err := strconv.Atoi(c.Ctx.GetCookie("user_id"))
	if err != nil {
		resp.ErrorCode = flash_sell.InvalidParms
		resp.ErrorMsg = "非法用户ID"
		logs.Warn("请求参数错误，解析用户id失败, error: %v", err)
		return
	}

	req := &biz.Req{
		ProductId:    productId,
		Source:       source,
		AuthCode:     autCode,
		FlashTime:    flashTime,
		Nance:        nance,
		UserAuthSign: userAuthSign,
		UserId:       userId,
		AccessTime:   time.Now(),
	}

	// 2. 业务逻辑执行
	bizData, bizErrCode, err := biz.FlashSell(req)
	if err != nil || bizErrCode != flash_sell.Succeed {
		resp.Data["biz_data"] = bizData
		resp.ErrorCode = bizErrCode
		resp.ErrorMsg = "服务内部处理错误"
		logs.Error("Flash Sell 调用失败, product_id: %v, autCode: %v, time: %v, nance: %v, biz error code: %v, error: %v", productId, source, autCode, flashTime, nance, bizErrCode, err)
		return
	}

}

func (c *FlashSellController) FlashSellInfo() {
	resp := biz.Resp{
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
