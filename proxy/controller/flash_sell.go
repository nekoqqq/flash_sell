package controller

import (
	"github.com/astaxie/beego"
	"runtime"
)

type FlashSellController struct {
	beego.Controller // 继承
}

func (c *FlashSellController) FlashSell() {
	c.Data["json"] = map[string]interface{}{
		"success":    true,
		"goroutines": runtime.NumGoroutine(),
	}
	c.ServeJSON()
}
func (c *FlashSellController) FlashSellInfo() {
	c.Data["json"] = "flash sell information"
	c.ServeJSON()
}
