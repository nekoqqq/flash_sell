package main

import (
	"flash_sell"
	"flash_sell/Proxy/controller"
	"github.com/astaxie/beego"
	"github.com/astaxie/beego/logs"
)

func main() {
	err := flash_sell.InitConfig()
	if err != nil {
		panic(err)
	}
	beego.Router("/flash_sell", &controller.FlashSellController{}, "*:FlashSell") // *表示GET和POST等都支持
	// 秒杀查询
	beego.Router("/info", &controller.FlashSellController{}, "*:FlashSellInfo")
	logs.Debug("enter router")
	beego.Run()
}
