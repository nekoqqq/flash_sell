package controller

import "github.com/astaxie/beego"

type FlashSellController struct {
	beego.Controller // 继承
}

func (c *FlashSellController) FlashSell() {
	c.Data["json"] = "flash sell"
	c.ServeJSON()
}
func (c *FlashSellController) FlashSellInfo() {
	c.Data["json"] = "flash sell information"
	c.ServeJSON()
}
